<?php

class UnifiControllerDiscovery extends IPSModule
{
    public function Create()
    {
        parent::Create();
        $this->RegisterAttributeString('devices', '[]');

        $this->RegisterMessage(0, IPS_KERNELMESSAGE);
        $this->RegisterMessage(0, IPS_KERNELSTARTED);
        $this->RegisterTimer('Discovery', 0, 'UnifiControllerDiscovery_Discover($_IPS[\'TARGET\']);');
    }

    public function ApplyChanges()
    {
        parent::ApplyChanges();

        if (IPS_GetKernelRunlevel() !== KR_READY) {
            return;
        }

        $this->WriteAttributeString('devices', json_encode($this->DiscoverDevices()));
        $this->SetTimerInterval('Discovery', 300000);

        // Status Error Kategorie zum Import auswählen
        $this->SetStatus(102);
    }

    public function MessageSink($TimeStamp, $SenderID, $Message, $Data)
    {
        switch ($Message) {
            case IM_CHANGESTATUS:
                if ($Data[0] === IS_ACTIVE) {
                    $this->ApplyChanges();
                }
                break;

            case IPS_KERNELMESSAGE:
                if ($Data[0] === KR_READY) {
                    $this->ApplyChanges();
                }
                break;
            case IPS_KERNELSTARTED:
                $this->WriteAttributeString('devices', json_encode($this->DiscoverDevices()));
                break;

            default:
                break;
        }
    }

    public function GetDevices()
    {
        $devices = $this->ReadPropertyString('devices');

        return $devices;
    }

    public function Discover()
    {
        $this->LogMessage($this->Translate('Background Discovery of Chromecast devices'), KL_NOTIFY);

        $devices = json_encode($this->DiscoverDevices());
        $this->WriteAttributeString('devices', $devices);

        return $devices;
    }

    /*
     * Configuration Form
     */

    /**
     * build configuration form.
     *
     * @return string
     */
    public function GetConfigurationForm()
    {
        // return current form
        $Form = json_encode(
            [
                'elements' => [],
                'actions'  => $this->FormActions(),
                'status'   => $this->FormStatus(), ]
        );

        return $Form;
    }

    /**
     * return form actions by token.
     *
     * @return array
     */
    protected function FormActions()
    {
        $form = [
            [
                'name'     => 'UnifiControllerDiscovery',
                'type'     => 'Configurator',
                'rowCount' => 20,
                'add'      => false,
                'delete'   => true,
                'sort'     => [
                    'column'    => 'name',
                    'direction' => 'ascending', 
                ],
                'columns'  => [
                    [
                        'label' => 'name',
                        'name'  => 'name',
                        'width' => 'auto', 
                    ],
                    [
                        'label' => 'type',
                        'name'  => 'type',
                        'width' => 'auto', 
                    ],
                    [
                        'label' => 'ip',
                        'name'  => 'ip',
                        'width' => 'auto', 
                    ],
                ],
                'values'   => $this->Get_ListConfiguration(), 
            ], 
        ];

        return $form;
    }

    /**
     * return from status.
     *
     * @return array
     */
    protected function FormStatus()
    {
        $form = [
            [
                'code'    => 101,
                'icon'    => 'inactive',
                'caption' => 'Creating instance.', ],
            [
                'code'    => 102,
                'icon'    => 'active',
                'caption' => 'Unifi Controller Discovery created.', ],
            [
                'code'    => 104,
                'icon'    => 'inactive',
                'caption' => 'interface closed.', ],
            [
                'code'    => 201,
                'icon'    => 'inactive',
                'caption' => 'Please follow the instructions.', ], ];

        return $form;
    }

    /**
     * Liefert alle Geräte.
     *
     * @return array configlist all devices
     */
    private function Get_ListConfiguration()
    {
        $config_list = [];
        $DeviceIdList = IPS_GetInstanceListByModuleID('{6064EC15-6A7C-42C1-81D3-B299178C0C27}'); // Chromecast Device
        $devices = $this->DiscoverDevices();
        $this->SendDebug('Discovered Unifi Controllers', json_encode($devices), 0);
        
        if (!empty($devices)) {
            foreach ($devices as $device) {
                $instanceID = 0;
                foreach ($DeviceIdList as $DeviceId) {
                    if ($device['uuid'] == IPS_GetProperty($DeviceId, 'uuid')) {
                        $device_name = IPS_GetName($DeviceId);
                        $this->SendDebug(
                            'Unifi Controller Discovery', 'device found: ' . utf8_decode($device_name) . ' (' . $DeviceId . ')', 0
                        );
                        $instanceID = $DeviceId;
                    }
                }

                $config_list[] = [
                    'instanceID' => $instanceID,
                    'uuid'       => $device['uuid'],
                    'name'       => $device['name'],
                    'ip'         => $device['ip'],
                    'type'       => $device['type'],
                    'create'     => [
                        [
                            'moduleID'      => '{6064EC15-6A7C-42C1-81D3-B299178C0C27}',
                            'configuration' => [
                                'uuid'       => $device['uuid'],
                                'ip'         => $device['ip']
                            ], 
                        ],
                        [
                            'moduleID'      => '{3CFF0FD9-E306-41DB-9B5A-9D06D38576C3}',
                            'configuration' => [
                                'Host' => $device['ip'],
                                'Port' => 443,
                                'Open' => false,
                                'UseSSL' => true,
                                'VerifyPeer' => false,
                                'VerifyHost' => false
                            ], 
                        ], 
                    ], 
                ];
            }
        }

        return $config_list;
    }

    private function DiscoverDevices(): array
    {
        $controllers = [
            [
                "type" => "UDM Pro",
                "ip" => "192.168.1.1"
            ]
        ];

        $this->SendDebug('Discover Response:', json_encode($controllers), 0);

        return $chromecasts;
    }
}