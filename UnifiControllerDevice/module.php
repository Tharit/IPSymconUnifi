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

        if($this->ReadPropertyString('username') && $this->ReadPropertyString('password')) {
            if (!IPS_GetProperty($parentID, 'Open')) {
                IPS_SetProperty($parentID, 'Open', true);
            }
        }

        parent::ApplyChanges();
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
        $this->SendDebug('Data', $data, 0);
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
    }

    private function Connect() {
        $this->Login();

        CSCK_SendText($this->GetConnectionID(), '');
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
    }
}