<?php

/**

 */
require_once(__DIR__ . '/../libs/ModuleUtilities.php');
require_once(__DIR__ . '/../libs/Websocket.php');
require_once(__DIR__ . '/../libs/UnifiAPI.php');

class UnifiProtect extends IPSModule
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
                IPS_RunScriptEx($script, ["Data" => json_encode($data['data'])]);
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
        $ip = $this->ReadPropertyString("ip");
        $username = $this->ReadPropertyString("username");
        $password = $this->ReadPropertyString("password");
        $cookie = $this->Login($ip, $username, $password);
        if($cookie === false) {
            $this->SendDebug('Login', 'Failed to get cookie', 0);
            $this->WSCDisconnect();
            return;
        }

        $bootstrap = $this->Request($ip, '/proxy/protect/api/bootstrap', $cookie);
        $this->SendDebug('Bootstrap', json_encode($bootstrap), 0);
        if(!$bootstrap || !isset($bootstrap['lastUpdateId'])) {
            $this->SendDebug('Login', 'Failed to load bootstrap data', 0);
            $this->WSCDisconnect(false);
        }

        $path = '/proxy/protect/ws/updates?lastUpdateId=' . $bootstrap['lastUpdateId'];
        $this->WSCConnect($path, $cookie);
    }

    private function Disconnect() {
        $canReconnect = $this->ReadPropertyString('username') && $this->ReadPropertyString('password');
        $this->WSCDisconnect($canReconnect);
    }
}