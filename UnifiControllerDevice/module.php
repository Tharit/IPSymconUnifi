<?php

require_once(__DIR__ . '/../libs/ModuleUtilities.php');
require_once(__DIR__ . '/../libs/Websocket.php');

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
        $this->RegisterTimer("PingTimer", 45000, 'IPS_RequestAction($_IPS["TARGET"], "TimerCallback", "PingTimer");');

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
        $this->RegisterMessage(0, IPS_KERNELSHUTDOWN);
        $this->RegisterMessage($this->InstanceID, FM_CONNECT);
        $this->RegisterMessage($this->InstanceID, FM_DISCONNECT);

        // clear state on startup
        $this->ResetState();

        // if this is not the initial creation there might already be a parent
        if($this->UpdateConnection() && $this->HasActiveParent()) {
            if($this->MUGetBuffer('State'))
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
            if($this->MUGetBuffer('State') === 2) {
                $this->Send('', WebSocketOPCode::close);
            }
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
        switch ($Message) {
            case IPS_KERNELSHUTDOWN:
                $parentID = $this->GetConnectionID();
                if (IPS_GetProperty($parentID, 'Open')) {
                    if($this->MUGetBuffer('State') === 2) {
                        $this->Send('', WebSocketOPCode::close);
                    }
                }
                break;
            case IPS_KERNELSTARTED:
            case FM_CONNECT:
                $this->SendDebug('STARTED / CONNECT', 'resetting connection');
                // if new parent and it is already active: connect immediately
                if($this->UpdateConnection() && $this->HasActiveParent()) {
                    $this->ResetState();
                    $this->Connect();
                }
                break;
            case FM_DISCONNECT:
                $this->ResetState();
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
        // unpack & decode data
        $data = json_decode($data);
        $data = utf8_decode($data->Buffer);

        $state = $this->MUGetBuffer('State');
        $data = $this->MUGetBuffer('Data') . $data;

        if($state === 0) {
            $this->SendDebug('Error', 'Unexpected data received while connecting', 0);
        } else if($state === 1) {
            try {
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

                    if (preg_match("/Sec-WebSocket-Accept: (.*)\r\n/", $data, $match)) {
                        if ($match[1] != $this->MUGetBuffer('HandshakeKey')) {
                            throw new Exception('Sec-WebSocket not match');
                        }
                    } else {
                        throw new Exception("Incomplete handshake response received");
                    }
                    $this->MUSetBuffer('Data', '');
                    $this->MUSetBuffer('State', 2);

                    $this->SetReceiveDataFilter('Ping|.*'.preg_quote('\"message\":\"events\"').'.*');

                    return;
                } else {
                    $this->SendDebug('Incomplete handshake response', $data, 0);
                    throw new Exception("Incomplete handshake response received");
                }
            }  catch (Exception $exc) {
                $this->SendDebug('Error', $exc->GetMessage(), 0);
                $this->Disconnect();
                trigger_error($exc->getMessage(), E_USER_NOTICE);
                return;
            }
        } else if($state === 2) {
            while (true) {
                if (strlen($data) < 2) {
                    break;
                }
                $Frame = new WebSocketFrame($data);
                if ($data == $Frame->Tail) {
                    break;
                }
                $data = $Frame->Tail;
                $Frame->Tail = null;
                $this->DecodeFrame($Frame);
            }
        }

        if(strlen($data) > 1024 * 1024) {
            $this->Disconnect();
            trigger_error("Maximum websocket frame size exceeded", E_USER_NOTICE);
            return;
        }

        $this->MUSetBuffer('Data', $data);
    }

    /**
     * Dekodiert die empfangenen Daten und sendet sie an die Childs bzw. bearbeitet die Anfrage.
     *
     * @param WebSocketFrame $Frame Ein Objekt welches einen kompletten Frame enthält.
     */
    private function DecodeFrame(WebSocketFrame $Frame)
    {
        $payloadType = $this->MUGetBuffer('PayloadType');

        switch ($Frame->OpCode) {
            case WebSocketOPCode::ping:
                $this->Send($Frame->Payload, WebSocketOPCode::pong);
                return;
            case WebSocketOPCode::close:
                $this->Send('', WebSocketOPCode::close);
                $this->MUSetBuffer('State', 3);
                return;
            case WebSocketOPCode::text:
            case WebSocketOPCode::binary:
                $this->MUSetBuffer('PayloadType', $Frame->OpCode);
                $data = $Frame->Payload;
                break;
            case WebSocketOPCode::continuation:
                $payloadData = $this->MUGetBuffer('PayloadData');
                $data = $payloadData . $Frame->Payload;
                break;
            case WebSocketOPCode::pong:
                $this->MUSetBuffer('PingPending', false);
                return;
            default:
                return;
        }

        if ($Frame->Fin) {
            // process data
            $this->SendDebug('Received Data', $data, 0);
            $data = '';
        }

        if(strlen($data) > 1024 * 1024) {
            $this->Disconnect();
            trigger_error("Maximum websocket payload size exceeded", E_USER_NOTICE);
            return;
        }

        $this->MUSetBuffer('PayloadData', $data);
    }

    public function RequestAction($ident, $value)
    {
        if($ident === 'TimerCallback') {
            if($this->MUGetBuffer('State') === 2) {
                $isPingPending = $this->MUGetBuffer('PingPending');
                if($isPingPending) {
                    $this->Disconnect();
                    trigger_error("Ping timeout", E_USER_NOTICE);
                    return;
                }

                $this->Send('Ping', WebSocketOPCode::ping);
                $this->MUSetBuffer('PingPending', true);
            }
        }

        $this->SendDebug('Action', $ident, 0);
    }

    //------------------------------------------------------------------------------------
    // external methods
    //------------------------------------------------------------------------------------
    

    //------------------------------------------------------------------------------------
    // module internals
    //------------------------------------------------------------------------------------
    private function ResetState() {
        $this->SetReceiveDataFilter('');
        $this->MUSetBuffer('Data', '');
        $this->MUSetBuffer('State', 0);
        $this->MUSetBuffer('PayloadType', 0);
        $this->MUSetBuffer('PayloadData', '');
    }

    private function Connect() {
        $this->MUSetBuffer('State', 0);
        $cookie = $this->Login();
        if($cookie === false) {
            $this->Disconnect();
            return;
        }
        $this->InitHandshake($cookie);
    }

    private function Disconnect() {
        $parentID = $this->GetConnectionID();
        if (!IPS_GetProperty($parentID, 'Open')) {
            return;
        }
        if($this->MUGetBuffer('State') === 2) {
            $this->Send('', WebSocketOPCode::close);
        }
        IPS_SetProperty($parentID, 'Open', false);
        @IPS_ApplyChanges($parentID);

        if($this->ReadPropertyString('username') && $this->ReadPropertyString('password')) {
            IPS_SetProperty($parentID, 'Open', true);
            @IPS_ApplyChanges($parentID);
        }
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

        if(!isset($headers['Set-Cookie'])) {
            $this->SendDebug('Cookie', 'Login failed', 0);
            return false;
        }
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
        $this->MUSetBuffer('HandshakeKey', $Key);

        $Header[] = 'GET ' . $path . ' HTTP/1.1';
        $Header[] = 'Host: ' . $this->ReadPropertyString("ip");
        $Header[] = 'Cookie: ' . $cookie;
        $Header[] = 'Upgrade: websocket';
        $Header[] = 'Connection: Upgrade';
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

        return true;
    }

    /**
     * Versendet RawData mit OpCode an den IO.
     *
     * @param string          $RawData
     * @param WebSocketOPCode $OPCode
     */
    private function Send(string $RawData, int $OPCode, $Fin = true)
    {
        $WSFrame = new WebSocketFrame($OPCode, $RawData);
        $WSFrame->Fin = $Fin;

        $JSON['DataID'] = '{79827379-F36E-4ADA-8A95-5F8D1DC92FA9}';
        $JSON['Buffer'] = utf8_encode($WSFrame->ToFrame(true));
        $JsonString = json_encode($JSON);
        parent::SendDataToParent($JsonString);
    }
}