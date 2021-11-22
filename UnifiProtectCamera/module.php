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
        $this->RegisterVariableString("LastRing", "Integer", "~UnixTimestamp");
        $this->RegisterVariableString("LastMotion", "Integer", "~UnixTimestamp");
        $this->RegisterVariableString("IsMotionDetected", "Boolean");

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