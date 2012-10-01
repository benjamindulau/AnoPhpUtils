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
    protected $index = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";


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

    public function urlEncode($guid)
    {
        $shortGuid = str_replace(array('-', '{', '}'), array('', '', ''), $guid);
        $shortGuid = substr($shortGuid, 6, 2) . substr($shortGuid, 4, 2) . substr($shortGuid, 2, 2) . substr($shortGuid, 0, 2)
            . substr($shortGuid, 10, 2) . substr($shortGuid, 8, 2)
            . substr($shortGuid, 14, 2) . substr($shortGuid, 12, 2)
            . substr($shortGuid, 16, 4)
            . substr($shortGuid, 20, 12);
        
        $shortGuid = hex2bin($shortGuid);        
        $shortGuid = base64_encode($shortGuid);
        $shortGuid = strtr($shortGuid, '/+', '_-');

        return rtrim($shortGuid, '=');
    }

    public function urlDecode($shortGuid)
    {
        $subject = strtr($shortGuid, '_-', '/+') . '==';
        $subject = base64_decode($subject);
        if ($subject == false || strlen($subject) < 16) {
            // Do something smart like throwing an exception
        }
        
        $subject = bin2hex($subject);
        $guid = substr($subject, 6, 2) . substr($subject, 4, 2) . substr($subject, 2, 2) . substr($subject, 0, 2)
            . '-' . substr($subject, 10, 2) . substr($subject, 8, 2)
            . '-' . substr($subject, 14, 2) . substr($subject, 12, 2)
            . '-' . substr($subject, 16, 4)
            . '-' . substr($subject, 20, 12);

        return $guid;
    }

    public function intToAlpha($in, $pad = false, $passPhrase = null, $encode = true)
    {
        $index = $this->index;
        if ($passPhrase !== null) {
            $index = $this->encodePassPhrase($index, $passPhrase);
        }
        $base = strlen($index);

        if (is_numeric($pad)) {
            $pad--;
            if ($pad > 0) {
                $in += pow($base, $pad);
            }
        }

        $out = "";
        for ($t = floor(log($in, $base)); $t >= 0; $t--) {
            $bcp = bcpow($base, $t);
            $a   = floor($in / $bcp) % $base;
            $out = $out . substr($index, $a, 1);
            $in  = $in - ($a * $bcp);
        }
        $out = strrev($out); // reverse

        return $encode ? base64_encode($out) : $out;
    }

    public function alphaToInt($in, $pad = false, $passPhrase = null, $decode = true)
    {
        $in = $decode ? base64_decode($in) : $in;
        $index = $this->index;
        if ($passPhrase !== null) {
            $index = $this->encodePassPhrase($index, $passPhrase);
        }
        $base = strlen($index);

        $in  = strrev($in);
        $out = 0;
        $len = strlen($in) - 1;
        for ($t = 0; $t <= $len; $t++) {
            $bcpow = bcpow($base, $len - $t);
            $out   = $out + strpos($index, substr($in, $t, 1)) * $bcpow;
        }

        if (is_numeric($pad)) {
            $pad--;
            if ($pad > 0) {
                $out -= pow($base, $pad);
            }
        }
        $out = sprintf('%F', $out);
        $out = substr($out, 0, strpos($out, '.'));

        return $out;
    }

    private function encodePassPhrase($in, $passPhrase)
    {
        for ($n = 0; $n < strlen($in); $n++) {
            $i[] = substr($in, $n, 1);
        }

        $passhash = hash('sha256', $passPhrase);
        $passhash = (strlen($passhash) < strlen($in))
            ? hash('sha512', $passPhrase)
            : $passhash;

        for ($n = 0; $n < strlen($in); $n++) {
            $p[] = substr($passhash, $n, 1);
        }

        array_multisort($p, SORT_DESC, $i);

        return implode($i);
    }
}