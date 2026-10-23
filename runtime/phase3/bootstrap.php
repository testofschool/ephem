<?php
/* Trusted deployment adapter, loaded before the clean baseline forks. */
final class EphemStateStream {
    public $context;
    public static int $fd = -1;
    private string $input = '';
    private string $output = '';
    public function stream_open($path, $mode, $options, &$opened_path): bool {
        if ($path !== 'ephem://state' || self::$fd < 0) return false;
        return true;
    }
    /* Return the size of a complete RESP2 array without assuming write boundaries. */
    private function frameSize(): ?int {
        $pos = strpos($this->input, "\r\n");
        if ($pos === false) return null;
        $count = substr($this->input, 0, $pos);
        if (!preg_match('/^\*[1-9][0-9]{0,3}$/D', $count)) throw new RuntimeException('RESP array');
        $count = (int)substr($count, 1);
        $pos += 2;
        for ($i = 0; $i < $count; $i++) {
            $end = strpos($this->input, "\r\n", $pos);
            if ($end === false) return null;
            $len = substr($this->input, $pos, $end - $pos);
            if (!preg_match('/^\$[0-9]{1,7}$/D', $len)) throw new RuntimeException('RESP bulk');
            $len = (int)substr($len, 1);
            if ($len > 1048576) throw new RuntimeException('RESP limit');
            $pos = $end + 2;
            if (strlen($this->input) < $pos + $len + 2) return null;
            if (substr($this->input, $pos + $len, 2) !== "\r\n") throw new RuntimeException('RESP terminator');
            $pos += $len + 2;
        }
        return $pos;
    }
    public function stream_write($data): int {
        if (strlen($this->input) + strlen($data) > 1048576) throw new RuntimeException('RESP input limit');
        $this->input .= $data;
        while (($len = $this->frameSize()) !== null) {
            $frame = substr($this->input, 0, $len);
            $this->input = substr($this->input, $len);
            $reply = ephem_state_exchange($frame);
            if (strlen($this->output) + strlen($reply) > 1048576) throw new RuntimeException('RESP output limit');
            $this->output .= $reply;
        }
        return strlen($data);
    }
    public function stream_read($count): string {
        $result = substr($this->output, 0, $count);
        $this->output = substr($this->output, strlen($result));
        return $result;
    }
    /* Draining one reply is not EOF on a bidirectional database connection. */
    public function stream_eof(): bool { return false; }
    public function stream_flush(): bool { return $this->input === ''; }
    public function stream_stat(): array { return []; }
    public function stream_set_option($option, $arg1, $arg2): bool { return false; }
    public function stream_close(): void {
        if ($this->input !== '') throw new RuntimeException('incomplete state command');
    }
}
if (!stream_wrapper_register('ephem', EphemStateStream::class)) throw new RuntimeException('register state wrapper');
