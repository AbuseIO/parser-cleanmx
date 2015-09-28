<?php

namespace AbuseIO\Parsers;

use ReflectionClass;
use Log;

class Cleanmx extends Parser
{
    public $parsedMail;
    public $arfMail;

    /**
     * Create a new Cleanmx instance
     */
    public function __construct($parsedMail, $arfMail)
    {
        $this->parsedMail = $parsedMail;
        $this->arfMail = $arfMail;
    }

    /**
     * Parse attachments
     * @return Array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        // Generalize the local config based on the parser class name.
        $reflect = new ReflectionClass($this);
        $this->configBase = 'parsers.' . $reflect->getShortName();

        Log::info(
            get_class($this). ': Received message from: '.
            $this->parsedMail->getHeader('from') . " with subject: '" .
            $this->parsedMail->getHeader('subject') . "' arrived at parser: " .
            config("{$this->configBase}.parser.name")
        );

        // Define array where all events are going to be saved in.
        $events = [ ];

        /**
         *  Try to find ARF report.
         *  Some notification emails do not contain an ARF report. Instead they
         *  contain a 'table row'-ish with abuse info (good job on keeping
         *  things simple cleanmx!). In that case we jump down and parse the
         *  email body.
         */
        foreach ($this->parsedMail->getAttachments() as $attachment) {
            // Only use the Cleanmx formatted files, skip all others
            if (preg_match(config("{$this->configBase}.parser.report_file"), $attachment->filename)) {
                $raw_report = $attachment->getContent();
                break;
            }
        }

        // We found an ARF report, yay!
        if (!empty($raw_report)) {
            preg_match_all('/([\w\-]+): (.*)[ ]*\r?\n/', $raw_report, $match);
            $report = array_combine($match[1], array_map('trim', $match[2]));
            if (empty($report['Report-Type'])) {
                return $this->failed(
                    "Unabled to detect feed because of required field Report-Type is missing"
                );
            }

            $feedName = $report['Report-Type'];

            // If feed is known and enabled, validate data and save report
            if ($this->isKnownFeed($feedName) && $this->isEnabledFeed($feedName)) {
                // Sanity checks (skip if required fields are unset)
                if ($this->hasRequiredFields($feedName, $report) === true) {
                    $events[] = [
                        'source'        => config("{$this->configBase}.parser.name"),
                        'ip'            => $report['Source'],
                        'domain'        => false,
                        'uri'           => false,
                        'class'         => config("{$this->configBase}.feeds.{$feedName}.class"),
                        'type'          => config("{$this->configBase}.feeds.{$feedName}.type"),
                        'timestamp'     => strtotime($report['Date']),
                        'information'   => json_encode($report),
                    ];
                } else {
                    return $this->failed(
                        "Required field {$this->requiredField} is missing in the report or config is incorrect."
                    );
                }
            } else {
                return $this->failed(
                    "Detected feed '{$feedName}' is unknown or disabled."
                );
            }

        } else {
            // Didn't find an ARF report, go scrape the email body!
            $body = $this->parsedMail->getMessageBody();
            preg_match_all(
                '/\n\|([^\|]*)[ ]*\|([^\|]*)[ ]*\|([^\|]*)[ ]*\|([^\|]*)[ ]*\|([^\|]*)[ ]*\|([^\| \r\n]*)/',
                $body,
                $regs
            );
            array_shift($regs);

            $reports = [ ];
            foreach ($regs as $r) {
                $name = trim(array_shift($r));
                foreach ($r as $i => $value) {
                    $reports[$i][$name] = trim($value);
                }
            }

            // What's the report type
            $subject = $this->parsedMail->getHeader('subject');
            $subjectMap = array(
                '/clean-mx-portals/'    => 'portals',
                '/clean-mx-viruses/'    => 'viruses',
                '/clean-mx-phishing/'   => 'phishing',
            );

            foreach ($subjectMap as $regex => $t) {
                if (preg_match($regex, $subject)) {
                    $type = $t;
                    break;
                }
            }

            switch ($type) {
                case 'phishing':
                    $feedName = 'clean-mx-phishing';
                    break;

                case 'viruses':
                    $feedName = 'clean-mx-viruses';
                    break;

                case 'portals':
                    $portalFeeds = [
                        'cleanmx_phish',
                        'cleanmx_spamvertized',
                        'cleanmx_generic',
                        'defaced_site',
                        'cysc.blacklisted.file.gd_url_cloud',
                        'JS/Decdec.psc',
                        'HIDDENEXT/Worm.Gen',
                        'unknown_html_RFI_php',
                    ];
                    break;
                default:
                    // If we didn't find any report type, go to next report
                    continue;
            }

            // Save reports
            foreach ($reports as $report) {
                if ($type == 'phishing') {
                    if (!empty($report['virusname']) && in_array($report['virusname'], $portalFeeds)) {
                        $feedName = $report['virusname'];
                    }
                }

                // If feed is known and enabled, validate data and save report
                if ($this->isKnownFeed($feedName) &&
                    $this->isEnabledFeed($feedName)) {
                    // Sanity checks (skip if required fields are unset)
                    if ($this->hasRequiredFields($feedName, $report) === true) {
                        $events[] = [
                            'source'        => config("{$this->configBase}.parser.name"),
                            'ip'            => $report['ip'],
                            'class'         => config("{$this->configBase}.feeds.{$feedName}.class"),
                            'type'          => config("{$this->configBase}.feeds.{$feedName}.type"),
                            'domain'        => (isset($report['domain'])) ? $report['domain'] : false,
                            'uri'           => (isset($report['Url'])) ? $report['Url'] : false,
                            'timestamp'     => strtotime($report['date']),
                            'information'   => json_encode($report),
                        ];
                    } else {
                        return $this->failed(
                            "Required field ${column} is missing in the report or config is incorrect."
                        );
                    }
                } else {
                    return $this->failed(
                        "Detected feed '{$feedName}' is unknown or disabled."
                    );
                }
            }
        }

        return $this->success($events);
    }
}
