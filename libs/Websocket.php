<?php

/**
 * Based on code from on IPSNetwork by Nall-chan
 * https://github.com/Nall-chan/IPSNetwork
 */

/**
 * Alle OpCodes für einen Websocket-Frame.
 */
class WebSocketOPCode
{
    const continuation = 0x0;
    const text = 0x1;
    const binary = 0x2;
    const close = 0x8;
    const ping = 0x9;
    const pong = 0xA;

    /**
     *  Liefert den Klartext zu einem OPCode.
     *
     * @param int $Code
     *
     * @return string
     */
    public static function ToString(int $Code)
    {
        switch ($Code) {
            case self::continuation:
                return 'continuation';
            case self::text:
                return 'text';
            case self::binary:
                return 'binary';
            case self::close:
                return 'close';
            case self::ping:
                return 'ping';
            case self::pong:
                return 'pong';
            default:
                return bin2hex(chr($Code));
        }
    }
}

/**
 * Wert bei Maskierung.
 */
class WebSocketMask
{
    const mask = 0x80;
}

function readLong(string $binary) : string {
    $result = "0";
    $result = bcadd($result, unpack("n", substr($binary, 0, 2))[1]);
    $result = bcmul($result, "65536");
    $result = bcadd($result, unpack("n", substr($binary, 2, 2))[1]);
    $result = bcmul($result, "65536");
    $result = bcadd($result, unpack("n", substr($binary, 4, 2))[1]);
    $result = bcmul($result, "65536");
    $result = bcadd($result, unpack("n", substr($binary, 6, 2))[1]);

    // if $binary is a signed long long
    // 9223372036854775808 is equal to (1 << 63) (note that this expression actually does not work even on 64-bit systems)
    if(bccomp($result, "9223372036854775808") !== -1) { // if $result >= 9223372036854775807
        $result = bcsub($result, "18446744073709551616"); // $result -= (1 << 64)
    }
    return $result;
}

/**
 * Ein Frame für eine Websocket Verbindung.
 */
class WebSocketFrame extends stdClass
{
    const Fin = 0x80;

    public $Fin = false;
    public $OpCode = WebSocketOPCode::continuation;
    public $Mask = false;
    public $MaskKey = '';
    public $Payload = '';
    public $PayloadRAW = '';
    public $Tail = null;

    /**
     * Erzeugt einen Frame anhand der übergebenen Daten.
     *
     * @param object|string|null|WebSocketOPCode Aus den übergeben Daten wird das Objekt erzeugt
     * @param string $Payload Das Payload wenn Frame den WebSocketOPCode darstellt.
     */
    public function __construct($Frame = null, $Payload = null)
    {
        if (is_null($Frame)) {
            return;
        }
        if (is_object($Frame)) {
            if ($Frame->DataID == '') { //GUID Virtual IO TX
                $this->Fin = true;
                $this->OpCode = WebSocketOPCode::text;
                $this->Payload = utf8_decode($Frame->Buffer);
            }
            if ($Frame->DataID == '') { //GUID textFrame
                $this->Fin = true;
                $this->OpCode = WebSocketOPCode::text;
                $this->Payload = utf8_decode($Frame->Buffer);
            }
            if ($Frame->DataID == '') { //GUID BINFrame
                $this->Fin = true;
                $this->OpCode = WebSocketOPCode::binary;
                $this->Payload = utf8_decode($Frame->Buffer);
            }
            return;
        }
        if (!is_null($Payload)) {
            $this->Fin = true;
            $this->OpCode = $Frame;
            $this->Payload = $Payload;
            return;
        }

        $this->Fin = ((ord($Frame[0]) & WebSocketFrame::Fin) == WebSocketFrame::Fin) ? true : false;
        $this->OpCode = (ord($Frame[0]) & 0x0F);
        $this->Mask = ((ord($Frame[1]) & WebSocketMask::mask) == WebSocketMask::mask) ? true : false;

        $len = ord($Frame[1]) & 0x7F;
        $start = 2;
        if ($len == 126) {
            $len = unpack('n', substr($Frame, 2, 2))[1];
            $start = 4;
        } elseif ($len == 127) {
            $len = intval(readLong(substr($Frame, 2, 8)));
            $start = 10;
        }
        if ($this->Mask) {
            $this->MaskKey = substr($Frame, $start, 4);
            $start = $start + 4;
        }
        //Prüfen ob genug daten da sind !
        if (strlen($Frame) >= $start + $len) {
            $this->Payload = substr($Frame, $start, $len);
            if ($this->Mask and ($len > 0)) {
                for ($i = 0; $i < strlen($this->Payload); $i++) {
                    $this->Payload[$i] = $this->Payload[$i] ^ $this->MaskKey[$i % 4];
                }
            }
            $Frame = substr($Frame, $start + $len);
        }
        $this->Tail = $Frame;
    }

    /**
     * Liefert den Byte-String für den Versand an den IO-Parent.
     */
    public function ToFrame($Masked = false)
    {
        $Frame = chr(($this->Fin ? 0x80 : 0x00) | $this->OpCode);
        $len = strlen($this->Payload);
        $len2 = '';
        if ($len > 0xFFFF) {
            $len2 = pack('J', $len);
            $len = 127;
        } elseif ($len > 125) {
            $len2 = pack('n', $len);
            $len = 126;
        }
        $this->Mask = $Masked;
        if ($this->Mask and ($len > 0)) {
            $this->PayloadRAW = $this->Payload;
            $len = $len | WebSocketMask::mask;
            $this->MaskKey = openssl_random_pseudo_bytes(4);
            for ($i = 0; $i < strlen($this->Payload); $i++) {
                $this->Payload[$i] = $this->Payload[$i] ^ $this->MaskKey[$i % 4];
            }
        }
        $Frame .= chr($len);
        $Frame .= $len2;
        $Frame .= $this->MaskKey;
        $Frame .= $this->Payload;
        return $Frame;
    }
}

trait CustomWebSocketClient {
    protected function WSCCreate() {
        $this->RegisterTimer("PingTimer", 45000, 'IPS_RequestAction($_IPS["TARGET"], "WSC", "PingTimer");');
        $this->RegisterMessage(0, IPS_KERNELSHUTDOWN);

        $this->MUSetBuffer('Attempt', 0);
        $this->WSCResetState();
    }

    protected function WSCResetState() {
        $this->SetReceiveDataFilter('');
        
        $this->MUSetBuffer('Data', '');
        $this->MUSetBuffer('State', 0);
        $this->MUSetBuffer('PayloadType', 0);
        $this->MUSetBuffer('PayloadData', '');
        $this->MUSetBuffer('PingPending', false);
    }

    protected function WSCSetReceiveDataFilter($filter) {
        $this->MUSetBuffer('WSCReceiveDataFilter', $filter);
        if($this->MUGetBuffer('State') == 2) {
            if($filter) {
                $filter = '.*Ping.*|' . $filter;
                $this->SetReceiveDataFilter($filter);
            } else {
                $this->SetReceiveDataFilter('');
            }
        }
    }

    protected function WSCRequestAction($value) {
        $state = $this->MUGetBuffer('State');
        switch($value) {
            case 'PingTimer':
                if($state == 2) {
                    $isPingPending = $this->MUGetBuffer('PingPending');
                    if($isPingPending) {
                        $this->WSCDisconnect();
                        trigger_error("Ping timeout", E_USER_NOTICE);
                        return;
                    }

                    $this->WSCSend('Ping', WebSocketOPCode::ping);
                    $this->MUSetBuffer('PingPending', true);
                }
                break;
            case 'Reconnect':
                if($state == 3) {
                    $this->SendDebug('WSC Action', "State: " . $state, 0);
                    $parentID = $this->GetConnectionID();

                    if (IPS_GetProperty($parentID, 'Open')) {
                        IPS_SetProperty($parentID, 'Open', false);
                        IPS_ApplyChanges($parentID);
                    }
                } else if($state == 4) {
                    $this->SendDebug('WSC Action', "State: " . $state, 0);

                    $parentID = $this->GetConnectionID();

                    $this->WSCResetState();

                    if (!IPS_GetProperty($parentID, 'Open')) {
                        IPS_SetProperty($parentID, 'Open', true);
                        IPS_ApplyChanges($parentID);
                    }
                }
                break;
        }
    }

    protected function WSCMessageSink($TimeStamp, $SenderID, $Message, $Data) {
        switch ($Message) {
            case IPS_KERNELSHUTDOWN:
                $parentID = $this->GetConnectionID();
                if (IPS_GetProperty($parentID, 'Open')) {
                    if($this->MUGetBuffer('State') === 2) {
                        $this->WSCSend('', WebSocketOPCode::close);
                    }
                }
                break;
            case IM_CHANGESTATUS:
                // skip if no change
                if($Data[0] == $Data[1]) return;

                $state = $this->MUGetBuffer('State');
                
                $this->SendDebug('CHANGESTATUS', 'New: ' . $Data[0] . " | Old: " . $Data[1] . " | State: " . $state, 0);

                if ($Data[0] === IS_ACTIVE) {
                    if($state == 0) {
                        $this->WSCOnReady();
                    }
                } else if($state == 3) {
                    // expected disconnect
                    // can be triggered by RequestAction manually setting Open to false, OR by socket state change.. whichever happens first
                    // if both get triggered, that is also fine
                    $this->MUSetBuffer('State', 4);
                    IPS_RunScriptText('IPS_Sleep(1000); IPS_RequestAction(' . $this->InstanceID . ', "WSC", "Reconnect");');
                } else if($state > 0) {
                    // unexpected disconnect to be handled
                    // notify handler & prepare for reconnect
                    $this->WSCOnDisconnect();
                    $this->WSCResetState();
                }
                break;
        }
    }

    /**
     *
     */
    protected function WSCConnect($ip, $path, $cookie)
    {
        $this->MUSetBuffer('Attempt', $this->MUGetBuffer('Attempt') + 1);

        $SendKey = base64_encode(openssl_random_pseudo_bytes(16));
        $Key = base64_encode(sha1($SendKey . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
        $this->MUSetBuffer('HandshakeKey', $Key);

        $Header[] = 'GET ' . $path . ' HTTP/1.1';
        $Header[] = 'Host: ' . $ip;
        $Header[] = 'Cookie: ' . $cookie;
        $Header[] = 'Upgrade: websocket';
        $Header[] = 'Connection: Upgrade';
        $Header[] = 'Sec-WebSocket-Key: ' . $SendKey;
        $Header[] = 'Sec-WebSocket-Version: 13';
        $Header[] = "\r\n";
        $SendData = implode("\r\n", $Header);
        //$this->SendDebug('Send Handshake', $SendData, 0);

        $this->MUSetBuffer('State', 1);

        $JSON['DataID'] = '{79827379-F36E-4ADA-8A95-5F8D1DC92FA9}';
        $JSON['Buffer'] = utf8_encode($SendData);
        $JsonString = json_encode($JSON);
        parent::SendDataToParent($JsonString);

        return true;
    }

    protected function WSCGetState() {
        return $this->MUGetBuffer('State');
    } 

    protected function WSCDisconnect($canReconnect = true) {
        $this->SendDebug('Disconnect', 'Requested disconnect...', 0);

        $parentID = $this->GetConnectionID();

        if(!IPS_GetProperty($parentID, 'Open')) {
            $this->WSCResetState();
            return;
        }

        if($this->MUGetBuffer('State') === 2) {
            $this->WSCSend('', WebSocketOPCode::close);
        }
        
        $this->MUSetBuffer('State', 3);
        
        $attempt = $this->MUGetBuffer('Attempt');

        $this->SendDebug('Disconnect', 'Scheduled in ' . $attempt . ' seconds...', 0);
        $this->MUSetBuffer('CanReconnect', $canReconnect);
        IPS_RunScriptText('IPS_Sleep(' . ($attempt * 1000). '); IPS_RequestAction(' . $this->InstanceID . ', "WSC", "Reconnect");');
    }

    protected function WSCReceiveData($data)
    {
        // unpack & decode data
        $data = json_decode($data);
        $data = utf8_decode($data->Buffer);

        $state = $this->MUGetBuffer('State');
        $data = $this->MUGetBuffer('Data') . $data;

        if($state === 0) {
            $this->SendDebug('Error', 'Unexpected data received while connecting', 0);
            $this->WSCDisconnect();
            return;
        } else if($state === 1) {
            try {
                if (strpos($data, "\r\n\r\n") !== false) {
                    //$this->SendDebug('Handshake response', $data, 0);

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
                    $this->MUGetBuffer('Attempt', 0);
                    $this->WSCOnConnect();

                    $filter = $this->MUGetBuffer('WSCReceiveDataFilter');
                    if($filter) {
                        $filter = '.*Ping.*|'.$filter;
                        $this->SetReceiveDataFilter($filter);
                    }
                    return;
                } else {
                    $this->SendDebug('Incomplete handshake response', $data, 0);
                    throw new Exception("Incomplete handshake response received");
                }
            }  catch (Exception $exc) {
                $this->SendDebug('Error', $exc->GetMessage(), 0);
                $this->WSCDisconnect();
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
                $this->WSCDecodeFrame($Frame);
            }
        } else if($state === 3) {
            $this->SendDebug('Warning', 'Unexpected data received after sending close packet', 0);
            return;
        }

        if(strlen($data) > 1024 * 1024) {
            $this->WSCDisconnect();
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
    private function WSCDecodeFrame($Frame)
    {
        $payloadType = $this->MUGetBuffer('PayloadType');

        switch ($Frame->OpCode) {
            case WebSocketOPCode::ping:
                $this->WSCSend($Frame->Payload, WebSocketOPCode::pong);
                return;
            case WebSocketOPCode::close:
                $this->WSCSend('', WebSocketOPCode::close);
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
            //$this->SendDebug('Received Data', $data, 0);
            try {
                $this->WSCOnReceiveData($Frame->OpCode, $data);
            } catch(Exception $e) {
                trigger_error("Error in websocket data handler: " . $exc->getMessage(), E_USER_WARNING);
                $this->SendDebug('Received Data', $data, 0);
            }
            $data = '';
        }

        if(strlen($data) > 1024 * 1024) {
            $this->WSCDisconnect();
            trigger_error("Maximum websocket payload size exceeded", E_USER_NOTICE);
            return;
        }

        $this->MUSetBuffer('PayloadData', $data);
    }

    /**
     * Versendet RawData mit OpCode an den IO.
     *
     * @param string          $RawData
     * @param WebSocketOPCode $OPCode
     */
    private function WSCSend(string $RawData, int $OPCode, $Fin = true)
    {
        $WSFrame = new WebSocketFrame($OPCode, $RawData);
        $WSFrame->Fin = $Fin;

        $JSON['DataID'] = '{79827379-F36E-4ADA-8A95-5F8D1DC92FA9}';
        $JSON['Buffer'] = utf8_encode($WSFrame->ToFrame(true));
        $JsonString = json_encode($JSON);
        parent::SendDataToParent($JsonString);
    }

    protected function WSCSendText(string $Data) {
        $this->WSCSend($Data, WebSocketOPCode::text);
    }

    protected function WSCSendBinary(string $Data) {
        $this->WSCSend($Data, WebSocketOPCode::binary);
    }
}