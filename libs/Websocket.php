<?php

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

/**
 * Ein Frame für eine Websocket Verbindung.
 */
class WebSocketFrame extends stdClass
{
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

        $this->Fin = ((ord($Frame[0]) & WebSocketState::Fin) == WebSocketState::Fin) ? true : false;
        $this->OpCode = (ord($Frame[0]) & 0x0F);
        $this->Mask = ((ord($Frame[1]) & WebSocketMask::mask) == WebSocketMask::mask) ? true : false;

        $len = ord($Frame[1]) & 0x7F;
        $start = 2;
        if ($len == 126) {
            $len = unpack('n', substr($Frame, 2, 2))[1];
            $start = 4;
        } elseif ($len == 127) {
            $len = unpack('J', substr($Frame, 2, 8))[1];
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