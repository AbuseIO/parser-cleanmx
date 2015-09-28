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
            'class'     => 'Login attack',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Source',
                'Date',
            ],
        ],

        'info' => [
            'class'     => 'Informational',
            'type'      => 'Info',
            'enabled'   => true,
            'fields'    => [
                'Source',
                'Date',
            ],
        ],

        'harvesting' => [
            'class'     => 'Harvesting',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Source',
                'Date',
            ],
        ],

        'hack-attack' => [
            'class'     => 'Hack attack',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Source',
                'Date',
            ],
        ],

        'comment spam' => [
            'class'     => 'Comment Spam',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Source',
                'Date',
            ],
        ],

        'Denial of service' => [
            'class'     => 'DDoS sending Server',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Source',
                'Date',
            ],
        ],

        // Feeds not coming from ARF reports
        'clean-mx-phishing' => [
            'class'     => 'Phishing website',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'clean-mx-viruses' => [
            'class'     => 'Malware infection',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'cleanmx_phish' => [
            'class'     => 'Phishing website',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'cleanmx_spamvertized' => [
            'class'     => 'Spamvertised web site',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'cleanmx_generic' => [
            'class'     => 'Compromised website',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'defaced_site' => [
            'class'     => 'Compromised website',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'cysc.blacklisted.file.gd_url_cloud' => [
            'class'     => 'Compromised website',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'JS/Decdec.psc' => [
            'class'     => 'Malware infection',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'HIDDENEXT/Worm.Gen' => [
            'class'     => 'Malware infection',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

        'unknown_html_RFI_php' => [
            'class'     => 'Compromised website',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'date',
            ],
        ],

    ],
];
