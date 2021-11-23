<?php

/*

on create / attach:
    - request latest status from parent!

*/

class UnifiProtectCamera extends IPSModule
{
    public function Create()
    {
        //Never delete this line!
        parent::Create();

        $this->RequireParent('{6808B0CF-DD86-4D0B-8B05-179D6FC2C690}'); // Unifi Protect

        $this->RegisterPropertyString('uuid', '');

        // variables
        $this->RegisterVariableInteger("LastMotion", "Last Motion", "~UnixTimestamp");
        $this->RegisterVariableBoolean("IsMotionDetected", "Is Motion Detected");

        $uuid = $this->ReadPropertyString('uuid');
        $this->SetReceiveDataFilter('.*'.preg_quote('\"id\":\"'.($uuid ? $uuid : 'xxxxxxxx').'\"').'.*');
    }

    private function SetupVariables($data) {
        if($data['hasChime']) {
            $this->RegisterVariableInteger("LastRing", "Last Ring", "~UnixTimestamp");
        }
    }

    private function RequestInit() {
        if(!$this->ReadPropertyString('uuid')) return;
        $this->SendDataToParent(json_encode([
            'DataID' => '{4DF70A1D-17C7-4B2B-BBEC-E39407BB8252}',
            'Buffer' => json_encode([
                'id' => $this->ReadPropertyString('uuid'),
                'action' => 'init'
            ])
        ]));
    }

    /**
     * Configuration changes
     */
    public function ApplyChanges()
    {
        parent::ApplyChanges();
        $uuid = $this->ReadPropertyString('uuid');
        $this->SetReceiveDataFilter('.*'.preg_quote('\"id\":\"'.($uuid ? $uuid : 'xxxxxxxx').'\"').'.*');
        $this->SendDebug('ApplyChanges', 'ApplyChanges', 0);
        $this->RequestInit();
    }

    public function ReceiveData($data) {
        $data = json_decode($data, true);
        $data = json_decode($data['Buffer'], true);

        $uuid = $this->ReadPropertyString('uuid');
        if($data['id'] !== $uuid) return;

        $data = $data['data'];

        if(isset($data['featureFlags'])) {
            $this->SetupVariables($data['featureFlags']);
        }

        if(isset($data['lastRing']) && $this->GetIDForIdent('LastRing')) {
            $value = $this->GetValue('LastRing');
            if($value != $data['lastRing']) {
                $this->SetValue('LastRing', round($data['lastRing']/1000));
            }
        }
        if(isset($data['lastMotion'])) {
            $value = $this->GetValue('LastMotion');
            if($value != $data['lastMotion']) {
                $this->SetValue('LastMotion', round($data['lastMotion']/1000));
            }
        }
        if(isset($data['isMotionDetected'])) {
            $value = $this->GetValue('IsMotionDetected');
            if($value != $data['isMotionDetected']) {
                $this->SetValue('IsMotionDetected', $data['isMotionDetected']);
            }
        }
        $this->SendDebug('Data', json_encode($data), 0);
    }

    public function MessageSink($TimeStamp, $SenderID, $Message, $Data)
    {
        switch ($Message) {
            case FM_CONNECT:
                $this->SendDebug('Message', 'FM_CONNECT', 0);
                $this->RequestInit();
                break;
        }
    }
}