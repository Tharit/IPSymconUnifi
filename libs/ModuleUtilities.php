<?php

trait ModuleUtilities {
    protected function MUSetBuffer($Name, $Daten)
    {
        $this->SetBuffer($Name, serialize($Daten));
    }

    protected function MUGetBuffer($Name)
    {
        return unserialize($this->GetBuffer($Name));
    }

    protected function UpdateConnection() {
        // parent is not available until kernel finished starting
        if (IPS_GetKernelRunlevel() !== KR_READY) {
            return false;
        }

        $newParentID = IPS_GetInstance($this->InstanceID)['ConnectionID'];
        $oldParentID = $this->MUGetBuffer('ConnectionID');

        $this->SendDebug('UpdateConnection',$newParentID . '|' . $oldParentID, 0);
        
        if($newParentID === $oldParentID) return false;

        if($oldParentID) {
            $this->UnregisterMessage($oldParentID, IM_CHANGESTATUS);
        }

        $this->MUSetBuffer('ConnectionID', $newParentID);
        
        if($newParentID) {
            $this->RegisterMessage($newParentID, IM_CHANGESTATUS);
        }
    
        return $newParentID > 0;
    }

    protected function GetConnectionID() {
        return $this->MUGetBuffer('ConnectionID');
    }
}