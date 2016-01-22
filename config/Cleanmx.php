<?php

return [
    'parser' => [
        'name'          => 'CleanMX',
        'enabled'       => true,
        'report_file'   => '/^report.txt/i',
        'sender_map'    => [
            '/abuse@clean-mx.de/',
        ],
        'body_map'      => [
            //
        ],
    ],

    'feeds' => [
        'login-attack' => [
            'class'     => 'LOGIN_ATTACK',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Source',
                'Date',
            ],
        ],

        'info' => [
            'class'     => 'INFORMATIONAL',
            'type'      => 'Info',
            'enabled'   => true,
            'fields'    => [
                'Source',
                'Date',
            ],
        ],

        'harvesting' => [
            'class'     => 'HARVESTING',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Source',
                'Date',
            ],
        ],

        'hack-attack' => [
            'class'     => 'HACK_ATTACK',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Source',
                'Date',
            ],
        ],

        'comment spam' => [
            'class'     => 'COMMENT_SPAM',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Source',
                'Date',
            ],
        ],

        'Denial of service' => [
            'class'     => 'DDOS_SENDING_SERVER',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Source',
                'Date',
            ],
        ],

        // Feeds not coming from ARF reports
        'clean-mx-phishing' => [
            'class'     => 'PHISING_WEBSITE',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'clean-mx-viruses' => [
            'class'     => 'MALWARE_INFECTION',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'cleanmx_phish' => [
            'class'     => 'PHISING_WEBSITE',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'cleanmx_spamvertized' => [
            'class'     => 'SPAMVERTISED_WEBSITE',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'cleanmx_generic' => [
            'class'     => 'COMPROMISED_WEBSITE',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'defaced_site' => [
            'class'     => 'COMPROMISED_WEBSITE',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'cysc.blacklisted.file.gd_url_cloud' => [
            'class'     => 'COMPROMISED_WEBSITE',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'JS/Decdec.psc' => [
            'class'     => 'MALWARE_INFECTION',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'HIDDENEXT/Worm.Gen' => [
            'class'     => 'MALWARE_INFECTION',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'unknown_html_RFI_php' => [
            'class'     => 'COMPROMISED_WEBSITE website',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

    ],
];
