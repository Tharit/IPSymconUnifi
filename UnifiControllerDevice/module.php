<?php

/**
API to fetch events

https://192.168.1.1/proxy/network/api/s/default/stat/event?start=1637485298&end=1637488857&_limit=100

 */
require_once(__DIR__ . '/../libs/ModuleUtilities.php');
require_once(__DIR__ . '/../libs/Websocket.php');

class UnifiController extends IPSModule
{
    use ModuleUtilities;
    use CustomWebSocketClient;

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
        $this->RegisterPropertyInteger('script', '0');

        // timers
        $this->WSCCreate();

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

        $this->WSCSetReceiveDataFilter('.*'.preg_quote('\"message\":\"events\"').'.*');

        // clear state on startup
        $this->ResetState();

        // if this is not the initial creation there might already be a parent
        if($this->UpdateConnection() && $this->HasActiveParent()) {
            $this->SendDebug('Module Create', 'Already connected', 0);
            $this->Disonnect();
        }
    }

    /**
     * Configuration changes
     */
    public function ApplyChanges()
    {
        $parentID = $this->GetConnectionID();

        if (IPS_GetProperty($parentID, 'Open')) {
            $this->WSCDisconnect(false);
            //IPS_SetProperty($parentID, 'Open', false);
            //@IPS_ApplyChanges($parentID);
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
        $this->WSCMessageSink($TimeStamp, $SenderID, $Message, $Data);

        switch ($Message) {
            case IPS_KERNELSTARTED:
            case FM_CONNECT:
                $this->SendDebug('STARTED / CONNECT', 'resetting connection', 0);
                // if new parent and it is already active: connect immediately
                if($this->UpdateConnection() && $this->HasActiveParent()) {
                    $this->ApplyChanges();
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

    public function ReceiveData($data) {
        $this->WSCReceiveData($data);
    }

    protected function WSCOnDisconnect() {
        return $this->ReadPropertyString('username') && $this->ReadPropertyString('password');
    }
 
    protected function WSCOnReceiveData($opCode, $data) {
        $script = $this->ReadPropertyInteger('script');
        if($script && @IPS_GetScript($script)) {
            $data = @json_decode($data, true);
            if($data != null && isset($data['data'])) {
                IPS_RunScriptEx($script, ["Data" => $data['data']]);
            }
        }
    }

    public function RequestAction($ident, $value)
    {
        if($ident === 'WSC') {
            $this->WSCRequestAction($value);
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
        $this->WSCResetState();
    }

    private function Connect() {
        if($this->WSCGetState() != 0) {
            IPS_LogMessage('WSC', 'Tried to connect while already connected');
            return;
        }
        $cookie = $this->Login();
        if($cookie === false) {
            $this->WSCDisconnect();
            return;
        }
        $path = '/proxy/network/wss/s/default/events?clients=v2';
        $this->WSCConnect($path, $cookie);
    }

    private function Disconnect() {
        $canReconnect = $this->ReadPropertyString('username') && $this->ReadPropertyString('password');
        $this->WSCDisconnect($canReconnect);
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
}