<?php

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

    /**
     * Configuration changes
     */
    public function ApplyChanges()
    {
        parent::ApplyChanges();
        $uuid = $this->ReadPropertyString('uuid');
        $this->SetReceiveDataFilter('.*'.preg_quote('\"id\":\"'.($uuid ? $uuid : 'xxxxxxxx').'\"').'.*');
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
}