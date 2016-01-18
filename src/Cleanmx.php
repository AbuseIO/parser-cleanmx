<?php

namespace AbuseIO\Parsers;

use AbuseIO\Models\Incident;

/**
 * Class Cleanmx
 * @package AbuseIO\Parsers
 */
class Cleanmx extends Parser
{
    /**
     * Create a new Cleanmx instance
     *
     * @param \PhpMimeMailParser\Parser $parsedMail phpMimeParser object
     * @param array $arfMail array with ARF detected results
     */
    public function __construct($parsedMail, $arfMail)
    {
        parent::__construct($parsedMail, $arfMail, $this);
    }

    /**
     * Parse attachments
     * @return array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        /**
         *  Try to find ARF report.
         *  Some notification emails do not contain an ARF report. Instead they
         *  contain a 'table row'-ish with abuse info (good job on keeping
         *  things simple cleanmx!). In that case we jump down and parse the
         *  email body.
         */
        $foundArf = false;
        foreach ($this->parsedMail->getAttachments() as $attachment) {
            // Only use the Cleanmx formatted files, skip all others
            if (preg_match(config("{$this->configBase}.parser.report_file"), $attachment->filename)) {
                $raw_report = $attachment->getContent();

                // We found an ARF report, yay!
                if (!empty($raw_report)) {
                    $foundArf = true;

                    if (!preg_match_all('/([\w\-]+): (.*)[ ]*\r?\n/', $raw_report, $matches)) {
                        $this->warningCount++;
                        continue;
                    }

                    $report = array_combine($matches[1], array_map('trim', $matches[2]));

                    if (!empty($report['Report-Type'])) {
                        $this->feedName = $report['Report-Type'];

                        // If feed is known and enabled, validate data and save report
                        if ($this->isKnownFeed() && $this->isEnabledFeed()) {
                            // Sanity check
                            if ($this->hasRequiredFields($report) === true) {
                                // incident has all requirements met, filter and add!
                                $report = $this->applyFilters($report);

                                $incident = new Incident();
                                $incident->source      = config("{$this->configBase}.parser.name");
                                $incident->source_id   = false;
                                $incident->ip          = $report['Source'];
                                $incident->domain      = false;
                                $incident->uri         = false;
                                $incident->class       = config("{$this->configBase}.feeds.{$this->feedName}.class");
                                $incident->type        = config("{$this->configBase}.feeds.{$this->feedName}.type");
                                $incident->timestamp   = strtotime($report['Date']);
                                $incident->information = json_encode($report);

                                $this->incidents[] = $incident;

                            }
                        }
                    } else {
                        $this->warningCount++;
                    }
                }
            }
        }

        if ($foundArf === false) {
            // Didn't find an ARF report, go scrape the email body!
            if (preg_match_all(
                '/\n\|([^\|]*)[ ]*\|([^\|]*)[ ]*\|([^\|]*)[ ]*\|([^\|]*)[ ]*\|([^\|]*)[ ]*\|([^\| \r\n]*)/',
                $this->parsedMail->getMessageBody(),
                $matches
            )
            ) {
                array_shift($matches);

                $reports = [ ];
                foreach ($matches as $r) {
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

                $type = 'default';
                foreach ($subjectMap as $regex => $t) {
                    if (preg_match($regex, $subject)) {
                        $type = $t;
                        break;
                    }
                }

                $portalFeeds = [ ];

                switch ($type) {
                    case 'phishing':
                        $this->feedName = 'clean-mx-phishing';
                        break;
                    case 'viruses':
                        $this->feedName = 'clean-mx-viruses';
                        break;
                    case 'portals':
                        $portalFeeds = [
                            'cleanmx_phish',
                            'cleanmx_spamvertized',
                            'cleanmx_generic',
                            'defaced_site',
                            'cysc_blacklisted_file_gd_url_cloud',
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
                    if ($type == 'portals') {
                        // Do not use dots in the name as it confuses the config base
                        $report['virusname'] = str_replace('.', '_', $report['virusname']);

                        if (!empty($report['virusname']) && in_array($report['virusname'], $portalFeeds)) {
                            $this->feedName = $report['virusname'];
                        }
                    }

                    if (!empty($report['Url'])) {
                        $urlInfo = parse_url($report['Url']);
                        if (!empty($urlInfo['path'])) {
                            $report['uri'] = $urlInfo['path'];
                        }
                    }

                    // If feed is known and enabled, validate data and save report
                    if ($this->isKnownFeed() && $this->isEnabledFeed()) {
                        // Sanity check
                        if ($this->hasRequiredFields($report) === true) {
                            // incident has all requirements met, filter and add!
                            $report = $this->applyFilters($report);

                            $incident = new Incident();
                            $incident->source      = config("{$this->configBase}.parser.name");
                            $incident->source_id   = false;
                            $incident->ip          = $report['ip'];
                            $incident->domain      = (isset($report['domain'])) ? $report['domain'] : false;
                            $incident->uri         = (isset($report['uri'])) ? $report['uri'] : false;
                            $incident->class       = config("{$this->configBase}.feeds.{$this->feedName}.class");
                            $incident->type        = config("{$this->configBase}.feeds.{$this->feedName}.type");
                            $incident->timestamp   = strtotime($report['date']);
                            $incident->information = json_encode($report);

                            $this->incidents[] = $incident;
                        }
                    }
                }
            }
        }

        return $this->success();
    }
}
