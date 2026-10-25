<?php
declare(strict_types=1);

namespace App;

final class Parser
{
    public function split(string $value): array
    {
        return explode(',', $value);
    }

    public function parse(string $value): array
    {
        return $this->split($value);
    }
}
