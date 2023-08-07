<?php

/**
API to fetch events

https://192.168.1.1/proxy/network/api/s/default/stat/event?start=1637485298&end=1637488857&_limit=100

 */
require_once(__DIR__ . '/../libs/ModuleUtilities.php');
require_once(__DIR__ . '/../libs/Websocket.php');
require_once(__DIR__ . '/../libs/UnifiAPI.php');

class UnifiController extends IPSModule
{
    use ModuleUtilities;
    use CustomWebSocketClient;
    use UnifiAPI;

    public function Create()
    {
        //Never delete this line!
        parent::Create();

        $this->RequireParent('{3CFF0FD9-E306-41DB-9B5A-9D06D38576C3}'); // IO Client Socket

        // properties
        $this->RegisterPropertyString('uuid', '');
        $this->RegisterPropertyString('username', '');
        $this->RegisterPropertyString('password', '');
        $this->RegisterPropertyInteger('script', '0');

        // timers
        $this->WSCCreate();

        // variables
        $this->RegisterVariableBoolean("Connected", "Connected");
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
            $this->Disconnect();
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
            default:
                break;
        }
    }

    public function ReceiveData($data) {
        $this->WSCReceiveData($data);
    }

    protected function WSCOnReady() {
        // reset state
        $this->ResetState();
        $this->Connect();
    }

    protected function WSCOnConnect() {
        $this->SetValue("Connected", true);
        $script = $this->ReadPropertyInteger('script');
        if($script && @IPS_GetScript($script)) {
            IPS_RunScriptEx($script, ["Data" => json_encode(["key" => "IPS_CONNECTED"])]);
        }
    }

    protected function WSCOnDisconnect() {
        $this->ResetState();
        $this->SetValue("Connected", false);
        $script = $this->ReadPropertyInteger('script');
        if($script && @IPS_GetScript($script)) {
            IPS_RunScriptEx($script, ["Data" => json_encode(["key" => "IPS_DISCONNECTED"])]);
        }
        return $this->ReadPropertyString('username') && $this->ReadPropertyString('password');
    }
 
    protected function WSCOnReceiveData($opCode, $data) {
        $script = $this->ReadPropertyInteger('script');
        if($script && @IPS_GetScript($script)) {
            $data = @json_decode($data, true);
            if($data != null && isset($data['data'])) {
                foreach($data['data'] as $event) {
                    IPS_RunScriptEx($script, ["Data" => json_encode($event)]);
                }
            }
        }
    }

    public function RequestAction($ident, $value)
    {
        if($ident === 'WSC') {
            $this->WSCRequestAction($value);
        }

        $this->SendDebug('Action', $ident . ' | ' . $value, 0);
    }

    //------------------------------------------------------------------------------------
    // external methods
    //------------------------------------------------------------------------------------
    public function GetClientDevice(string $mac) {
        $this->RefreshToken();
        $parentID = $this->GetConnectionID();
        $ip = IPS_GetProperty($parentID, 'Host');
        $cookie = $this->MUGetBuffer('cookie');
        $csrfToken = $this->MUGetBuffer('x-csrf-token');
        return $this->Request($ip, '/proxy/network/api/s/default/stat/user/' . $mac, $cookie, $csrfToken);
    }

    public function GetAccessDevices(string $mac) {
        $this->RefreshToken();
        $parentID = $this->GetConnectionID();
        $ip = IPS_GetProperty($parentID, 'Host');
        $cookie = $this->MUGetBuffer('cookie');
        $csrfToken = $this->MUGetBuffer('x-csrf-token');
        return $this->Request($ip, '/proxy/network/api/s/default/stat/device/' . $mac, $cookie, $csrfToken);
    }

    public function GetPortConfig() {
        $this->RefreshToken();
        $parentID = $this->GetConnectionID();
        $ip = IPS_GetProperty($parentID, 'Host');
        $cookie = $this->MUGetBuffer('cookie');
        $csrfToken = $this->MUGetBuffer('x-csrf-token');
        return $this->Request($ip, '/proxy/network/api/s/default/list/portconf/', $cookie, $csrfToken);
    }

    public function SetDeviceSettingsBase(string $deviceId, string $payload) {
        $this->RefreshToken();
        $parentID = $this->GetConnectionID();
        $ip = IPS_GetProperty($parentID, 'Host');
        $cookie = $this->MUGetBuffer('cookie');
        $csrfToken = $this->MUGetBuffer('x-csrf-token');
        return $this->Request($ip, '/proxy/network/api/s/default/rest/device/' . $deviceId, $cookie, $csrfToken, $payload, 'PUT');
    }

    //------------------------------------------------------------------------------------
    // module internals
    //------------------------------------------------------------------------------------
    private function RefreshToken() {
        $cookie = $this->MUGetBuffer('cookie');
        if(!$cookie) return;
        $parts = explode('=', $cookie);
        $token = $parts[1];

        $parts = explode('.', $token);
        $tokenData = json_decode(base64_decode($parts[1]), true);
        $expiration = $tokenData['exp'];
        $isValid = time() + 5 * 60 < $expiration;

        if($isValid) return;
        
        $this->SendDebug('RefreshToken', 'Token expired', 0);

        $parentID = $this->GetConnectionID();
        $ip = IPS_GetProperty($parentID, 'Host');
        $username = $this->ReadPropertyString("username");
        $password = $this->ReadPropertyString("password");
        $res = $this->Login($ip, $username, $password);
        if(!isset($res['cookie']) || $res['cookie'] === false) {
            $this->WSCDisconnect();
            return;
        }
        $this->MUSetBuffer('cookie', $res['cookie']);
        $this->MUSetBuffer('x-csrf-token', $res['x-csrf-token']);
    }

    private function ResetState() {
        $this->MUSetBuffer('cookie', '');
        $this->MUSetBuffer('x-csrf-token', '');
    }

    private function Connect() {
        if($this->WSCGetState() != 0) {
            IPS_LogMessage('Unifi Controller', 'Tried to connect while already connected');
            return;
        }
        $parentID = $this->GetConnectionID();
        $ip = IPS_GetProperty($parentID, 'Host');
        $username = $this->ReadPropertyString("username");
        $password = $this->ReadPropertyString("password");
        $res = $this->Login($ip, $username, $password);
        if(!isset($res['cookie']) || $res['cookie'] === false) {
            $this->WSCDisconnect();
            return;
        }
        $this->MUSetBuffer('cookie', $res['cookie']);
        $this->MUSetBuffer('x-csrf-token', $res['x-csrf-token']);
        $path = '/proxy/network/wss/s/default/events?clients=v2';
        $this->WSCConnect($ip, $path, $res['cookie']);
    }

    private function Disconnect() {
        $canReconnect = $this->ReadPropertyString('username') && $this->ReadPropertyString('password');
        $this->WSCDisconnect($canReconnect);
    }
}