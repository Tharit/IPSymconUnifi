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
        $this->RegisterVariableInteger("LastRing", "Last Ring", "~UnixTimestamp");
        $this->RegisterVariableInteger("LastMotion", "Last Motion", "~UnixTimestamp");
        $this->RegisterVariableBoolean("IsMotionDetected", "Is Motion Detected");

        $uuid = $this->ReadPropertyString('uuid');
        if($uuid) {
            $this->SetReceiveDataFilter('.*"id":"'.$uuid.'".*');
        } else {
            $this->SetReceiveDataFilter('.*"id":"xxxxxxxxx".*');
        }
    }

    /**
     * Configuration changes
     */
    public function ApplyChanges()
    {
        parent::ApplyChanges();
        $uuid = $this->ReadPropertyString('uuid');
        if($uuid) {
            $this->SetReceiveDataFilter('.*"id":"'.$uuid.'".*');
        } else {
            $this->SetReceiveDataFilter('.*"id":"xxxxxxxxx".*');
        }
    }

    public function ReceiveData($data) {
        $this->SendDebug('Data', $data);
    }
}