<?php

require_once(__DIR__ . '/../libs/ModuleUtilities.php');

class UnifiController extends IPSModule
{
    use ModuleUtilities;

    public function Create()
    {
        //Never delete this line!
        parent::Create();

        $this->RequireParent('{3CFF0FD9-E306-41DB-9B5A-9D06D38576C3}'); // IO Client Socket

        // properties
        $this->RegisterPropertyString('uuid', '');
        $this->RegisterPropertyString('ip', '');
        $this->RegisterPropertyString('username', '');
        $this->RegisterPropertyString('password', '');

        // timers
//        $this->RegisterTimer("PingTimer", 5000, 'IPS_RequestAction($_IPS["TARGET"], "TimerCallback", "PingTimer");');

        // variables
        /*
        $this->RegisterVariableString("Application", "Application");
        $this->RegisterVariableString("State", "State");
        $this->RegisterVariableString("Title", "Title");
        $this->RegisterVariableFloat("Volume", "Volume", "~Intensity.1");
        $this->EnableAction("Volume");
        */

        // messages
        $this->RegisterMessage(0, IPS_KERNELSTARTED);
        $this->RegisterMessage($this->InstanceID, FM_CONNECT);
        $this->RegisterMessage($this->InstanceID, FM_DISCONNECT);

        // clear state on startup
        $this->ResetState();

        // if this is not the initial creation there might already be a parent
        if($this->UpdateConnection() && $this->HasActiveParent()) {
            $this->Connect();
        }
    }

    /**
     * Configuration changes
     */
    public function ApplyChanges()
    {
        $parentID = $this->GetConnectionID();

        if (IPS_GetProperty($parentID, 'Open')) {
            IPS_SetProperty($parentID, 'Open', false);
            @IPS_ApplyChanges($parentID);
        }

        parent::ApplyChanges();

        if($this->ReadPropertyString('username') && $this->ReadPropertyString('password')) {
            if (!IPS_GetProperty($parentID, 'Open')) {
                IPS_SetProperty($parentID, 'Open', true);
                @IPS_ApplyChanges($parentID);
            }
        }
    }

    public function MessageSink($TimeStamp, $SenderID, $Message, $Data)
    {
        IPS_LogMessage("MessageSink", "Message from SenderID ".$SenderID." with Message ".$Message."\r\n Data: ".print_r($Data, true));

        switch ($Message) {
            case IPS_KERNELSTARTED:
            case FM_CONNECT:
                // if new parent and it is already active: connect immediately
                if($this->UpdateConnection() && $this->HasActiveParent()) {
                    $this->Connect();
                }
            case FM_DISCONNECT:
                $this->UpdateConnection();
                break;
            case IM_CHANGESTATUS:
                // reset state
                $this->ResetState();

                $this->SendDebug('CHANGESTATUS', json_encode($Data), 0);

                // if parent became active: connect
                if ($Data[0] === IS_ACTIVE) {
                    $this->Connect();
                }
                break;
            default:
                break;
        }
    }

    public function ReceiveData($data)
    {
        $state = $this->MUGetBuffer('State');
        $data = $this->MUGetBuffer('Data') . $data;

        if($state === 0) {
            $this->SendDebug('Error', 'Unexpected data received while connecting', 0);
        } else if($state === 1) {
            try {
                $this->SendDebug('Data', $data, 0);
                if (strpos($data, "\r\n\r\n") !== false) {
                    $this->SendDebug('Handshake response', $data, 0);

                    if (preg_match("/HTTP\/1.1 (\d{3}) /", $data, $match)) {
                        if ((int) $match[1] != 101) {
                            throw new Exception(HTTP_ERROR_CODES::ToString((int) $match[1]));
                        }
                    } else {
                        throw new Exception("Incomplete handshake response received");
                    }

                    if (preg_match("/Connection: (.*)\r\n/", $data, $match)) {
                        if (strtolower($match[1]) != 'upgrade') {
                            throw new Exception('Handshake "Connection upgrade" error');
                        }
                    } else {
                        throw new Exception("Incomplete handshake response received");
                    }

                    if (preg_match("/Upgrade: (.*)\r\n/", $data, $match)) {
                        if (strtolower($match[1]) != 'websocket') {
                            throw new Exception('Handshake "Upgrade websocket" error');
                        }
                    } else {
                        throw new Exception("Incomplete handshake response received");
                    }

                    if (preg_match("/Sec-WebSocket-Accept: (.*)\r\n/", $Result, $match)) {
                        if ($match[1] != $Key) {
                            throw new Exception('Sec-WebSocket not match');
                        }
                    } else {
                        throw new Exception("Incomplete handshake response received");
                    }
                    $this->MUSetBuffer('Data', '');
                    $this->MUSetBuffer('State', 2);
                    return;
                } else {
                    throw new Exception("Incomplete handshake response received");
                }
            }  catch (Exception $exc) {
                $this->Disconnect();
                trigger_error($exc->getMessage(), E_USER_NOTICE);
                return;
            }
        } else if($state === 2) {
            //$this->SendDebug('Data', $data, 0);
            return;
        }

        if(strlen($data) > 1024 * 1024) {
            $this->Disconnect();
            trigger_error("Maximum websocket frame size exceeded", E_USER_NOTICE);
            return;
        }

        $this->MUSetBuffer('Data', $data);
    }

    public function RequestAction($ident, $value)
    {
        $this->SendDebug('Action', $ident, 0);
    }

    //------------------------------------------------------------------------------------
    // external methods
    //------------------------------------------------------------------------------------
    

    //------------------------------------------------------------------------------------
    // module internals
    //------------------------------------------------------------------------------------
    private function ResetState() {
        $this->MUSetBuffer('Data', '');
        $this->MUSetBuffer('State', 0);
    }

    private function Connect() {
        $this->MUSetBuffer('State', 0);
        $cookie = $this->Login();
        $this->InitHandshake($cookie);
    }

    private function Disconnect() {
        $parentID = $this->GetConnectionID();
        if (!IPS_GetProperty($parentID, 'Open')) {
            return;
        }
        IPS_SetProperty($parentID, 'Open', false);
        @IPS_ApplyChanges($parentID);
        IPS_SetProperty($parentID, 'Open', true);
        @IPS_ApplyChanges($parentID);
    }

    private function Login() {
        $url = "https://" . $this->ReadPropertyString("ip") . "/api/auth/login";
        $username = $this->ReadPropertyString("username");
        $password = $this->ReadPropertyString("password");

        $headers = [];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HEADERFUNCTION, function( $curl, $header_line ) use (&$headers) {
            $idx = strpos($header_line,':');
            if($idx >= 1) {
                $name = substr($header_line, 0, $idx);
                $value = trim(substr($header_line, $idx + 1));
                $headers[$name] = $value;
            }
            return strlen($header_line);
        });
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(["username" => $username,"password" => $password]));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

        curl_exec($ch);
        curl_close($ch);

        $cookie = explode(';', $headers['Set-Cookie'])[0];

        $this->SendDebug('Cookie', $cookie, 0);

        return $cookie;
    }

    /**
     *
     */
    private function InitHandshake($cookie)
    {
        $path = '/proxy/network/wss/s/default/events?clients=v2';

        $SendKey = base64_encode(openssl_random_pseudo_bytes(16));
        $Key = base64_encode(sha1($SendKey . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));

        $Header[] = 'GET ' . $path . ' HTTP/1.1';
        $Header[] = 'Host: ' . $this->ReadPropertyString("ip");
        $Header[] = 'Cookie: ' . $cookie;
        $Header[] = 'Upgrade: websocket';
        $Header[] = 'Connection: Upgrade';
/*
        $Origin = $this->ReadPropertyString('Origin');
        if ($Origin != '') {
            if ($this->ReadPropertyInteger('Version') >= 13) {
                $Header[] = 'Origin: ' . $Origin;
            } else {
                $Header[] = 'Sec-WebSocket-Origin: ' . $Origin;
            }
        }
        $Protocol = $this->ReadPropertyString('Protocol');
        if ($Protocol != '') {
            $Header[] = 'Sec-WebSocket-Protocol: ' . $Protocol;
        }
    */

        $Header[] = 'Sec-WebSocket-Key: ' . $SendKey;
        $Header[] = 'Sec-WebSocket-Version: 13';
        $Header[] = "\r\n";
        $SendData = implode("\r\n", $Header);
        $this->SendDebug('Send Handshake', $SendData, 0);

        $this->MUSetBuffer('State', 1);

        $JSON['DataID'] = '{79827379-F36E-4ADA-8A95-5F8D1DC92FA9}';
        $JSON['Buffer'] = utf8_encode($SendData);
        $JsonString = json_encode($JSON);
        parent::SendDataToParent($JsonString);

        /*
            // Antwort lesen
            $Result = $this->WaitForResponse(WebSocketState::HandshakeReceived);
            if ($Result === false) {
                throw new Exception('no answer');
            }

            $this->SendDebug('Get Handshake', $Result, 0);

            if (preg_match("/HTTP\/1.1 (\d{3}) /", $Result, $match)) {
                if ((int) $match[1] != 101) {
                    throw new Exception(HTTP_ERROR_CODES::ToString((int) $match[1]));
                }
            }

            if (preg_match("/Connection: (.*)\r\n/", $Result, $match)) {
                if (strtolower($match[1]) != 'upgrade') {
                    throw new Exception('Handshake "Connection upgrade" error');
                }
            }

            if (preg_match("/Upgrade: (.*)\r\n/", $Result, $match)) {
                if (strtolower($match[1]) != 'websocket') {
                    throw new Exception('Handshake "Upgrade websocket" error');
                }
            }

            if (preg_match("/Sec-WebSocket-Accept: (.*)\r\n/", $Result, $match)) {
                if ($match[1] != $Key) {
                    throw new Exception('Sec-WebSocket not match');
                }
            }
        } catch (Exception $exc) {
            trigger_error($exc->getMessage(), E_USER_NOTICE);
            return false;
        }
        */

        return true;
    }
}