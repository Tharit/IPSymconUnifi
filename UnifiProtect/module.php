<?php

/**
    API description: https://github.com/hjdhjd/homebridge-unifi-protect/blob/master/docs/ProtectAPI.md

    - Login to the UniFi Protect controller and obtain the bootstrap JSON. The URL is: https://protect-nvr-ip/proxy/protect/api/bootstrap
    - Open the websocket to the updates URL. The URL is: wss://protect-nvr-ip/proxy/protect/ws/updates?lastUpdateId?lastUpdateId=X

    Header Frame (8 bytes)
    ----------------------
    Action Frame
    ----------------------
    Header Frame (8 bytes)
    ----------------------
    Data Frame

    Header:

    Byte Offset	Description	    Bits	Values
    0	        Packet Type	    8	    1 - action frame, 2 - payload frame.
    1	        Payload Format	8	    1 - JSON object, 2 - UTF8-encoded string, 3 - Node Buffer.
    2	        Deflated	    8	    0 - uncompressed, 1 - deflated / compressed (zlib-based).
    3	        Unknown	        8	    Always 0. Possibly reserved for future use by Ubiquiti?
    4-7	        Payload Size	32	    Size of payload in network-byte order (big endian).

    Action Frame

    Property	Description
    action	    What action is being taken. Known actions are add and update.
    id	        The identifier for the device we're updating.
    modelKey	The device model category that we're updating.
    newUpdateId	A new UUID generated on a per-update basis. This can be safely ignored it seems.

    Data Frame
    
    Payload Type	Description
    1	            JSON. If the action frame's action property is set to update and the modelKey property is not set to event (e.g. camera), this will always a subset of the configuration bootstrap JSON.
    2	            A UTF8-encoded string.
    3	            Node Buffer.

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
 

    protected function ParseFrame($data, &$offset) {
        // header
        $packetType = unpack('c', $data, $offset + 0)[1];
        $payloadFormat = unpack('c', $data, $offset + 1)[1];
        $deflated = unpack('c', $data, $offset + 2)[1];
        $payloadSize = unpack('N', $data, $offset + 4)[1];

        // action frame
        $offset += 8;
        $payload = substr($data, $offset, $payloadSize);
        if($deflated) {
            $payload = zlib_decode($payload);
        }
        $offset += $payloadSize;

        return [
            "format" => $payloadFormat,
            "data" => $payload
        ];
    }

    protected function WSCOnReceiveData($opCode, $data) {
        // header
        $offset = 0;
        $action = $this->ParseFrame($data, $offset);
        $data = $this->ParseFrame($data, $offset);

        if($action['format'] === 1 && $data['format'] === 1) {
            $actionJSON = json_decode($action['data'], true);
            $dataJSON = json_decode($data['data'], true);

            $this->SendDebug('data', $actionJSON['modelKey'] . ' ' . $actionJSON['id'] . ': ' . $data['data'], 0);

            $this->SendDataToChildren(json_encode([
                "DataID" => "{E2D9573A-39CC-49AC-A2AA-FB7A619A7970}",
                "Buffer" => json_encode(["id" => $actionJSON['id'], "data" => $dataJSON])
            ]));
            /*
            if($actionJSON['action'] === 'add' && $actionJSON['modelKey'] === 'event') {

                // ring events
                if($dataJSON['type'] === 'ring') {
                    $this->SendDebug('Ring', $dataJSON['camera'], 0);
                }

            }
            */
        } else {
            $this->SendDebug('data', $action . ' ' . $data, 0);
        }

        /*
        $script = $this->ReadPropertyInteger('script');
        if($script && @IPS_GetScript($script)) {
            $data = @json_decode($data, true);
            if($data != null && isset($data['data'])) {
                IPS_RunScriptEx($script, ["Data" => json_encode($data['data'])]);
            }
        }
        */
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

        $parentID = $this->GetConnectionID();
        $ip = IPS_GetProperty($parentID, 'Host');
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

        foreach($bootstrap['cameras'] as $camera) {
            $this->SendDataToChildren(json_encode([
                "DataID" => "{E2D9573A-39CC-49AC-A2AA-FB7A619A7970}",
                "Buffer" =>json_encode(["id"=>$camera["id"],"data"=>$camera])
            ]));
        }

        $path = '/proxy/protect/ws/updates?lastUpdateId=' . $bootstrap['lastUpdateId'];
        $this->WSCConnect($ip, $path, $cookie);
    }

    private function Disconnect() {
        $canReconnect = $this->ReadPropertyString('username') && $this->ReadPropertyString('password');
        $this->WSCDisconnect($canReconnect);
    }
}