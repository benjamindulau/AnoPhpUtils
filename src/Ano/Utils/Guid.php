<?php

/**
 * This file is part of the AnoPhpUtils library
 *
 * (c) anonymation <contact@anonymation.com>
 *
 */

namespace Ano\Utils;

/**
 * @author Benjamin Dulau <benjamin.dulau@anonymation.com>
 */
class Guid
{
    /**
     * Source and copyright : http://api.cakephp.org/class/string#method-Stringuuid
     *
     * @param string $salt
     *
     * @return string
     */
    public function generateGuid($salt = '')
    {
        $node = getenv('SERVER_ADDR');

        if (strpos($node, ':') !== false) {
            if (substr_count($node, '::')) {
                $node = str_replace(
                    '::', str_repeat(':0000', 8 - substr_count($node, ':')) . ':', $node
                );
            }
            $node = explode(':', $node);
            $ipSix = '';

            foreach ($node as $id) {
                $ipSix .= str_pad(base_convert($id, 16, 2), 16, 0, STR_PAD_LEFT);
            }
            $node = base_convert($ipSix, 2, 10);

            if (strlen($node) < 38) {
                $node = null;
            } else {
                $node = crc32($node);
            }
        } elseif (empty($node)) {
            $host = getenv('HOSTNAME');

            if (empty($host)) {
                $host = getenv('HOST');
            }

            if (!empty($host)) {
                $ip = gethostbyname($host);

                if ($ip === $host) {
                    $node = crc32($host);
                } else {
                    $node = ip2long($ip);
                }
            }
        } elseif ($node !== '127.0.0.1') {
            $node = ip2long($node);
        } else {
            $node = null;
        }

        if (empty($node)) {
            $node = crc32($salt);
        }

        if (function_exists('hphp_get_thread_id')) {
            $pid = hphp_get_thread_id();
        } elseif (function_exists('zend_thread_id')) {
            $pid = zend_thread_id();
        } else {
            $pid = getmypid();
        }

        if (!$pid || $pid > 65535) {
            $pid = mt_rand(0, 0xfff) | 0x4000;
        }

        list($timeMid, $timeLow) = explode(' ', microtime());
        $uuid = sprintf(
            "%08x-%04x-%04x-%02x%02x-%04x%08x", (int)$timeLow, (int)substr($timeMid, 2) & 0xffff,
            mt_rand(0, 0xfff) | 0x4000, mt_rand(0, 0x3f) | 0x80, mt_rand(0, 0xff), $pid, $node
        );

        return $uuid;
    }
}