<?php

namespace Illuminate\Tests\Hashing;

use Illuminate\Config\Repository as Config;
use Illuminate\Container\Container;
use Illuminate\Hashing\Argon2IdHasher;
use Illuminate\Hashing\ArgonHasher;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Hashing\HashManager;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class HasherTest extends TestCase
{
    public $hashManager;

    protected function setUp(): void
    {
        parent::setUp();

        $container = Container::setInstance(new Container);
        $container->singleton('config', fn () => new Config());

        $this->hashManager = new HashManager($container);
    }

    public function testEmptyHashedValueReturnsFalse()
    {
        $hasher = new BcryptHasher();
        $this->assertFalse($hasher->check('password', ''));
        $hasher = new ArgonHasher();
        $this->assertFalse($hasher->check('password', ''));
        $hasher = new Argon2IdHasher();
        $this->assertFalse($hasher->check('password', ''));
    }

    public function testNullHashedValueReturnsFalse()
    {
        $hasher = new BcryptHasher();
        $this->assertFalse($hasher->check('password', null));
        $hasher = new ArgonHasher();
        $this->assertFalse($hasher->check('password', null));
        $hasher = new Argon2IdHasher();
        $this->assertFalse($hasher->check('password', null));
    }

    public function testBasicBcryptHashing()
    {
        $hasher = new BcryptHasher;
        $value = $hasher->make('password');
        $this->assertNotSame('password', $value);
        $this->assertTrue($hasher->check('password', $value));
        $this->assertFalse($hasher->needsRehash($value));
        $this->assertTrue($hasher->needsRehash($value, ['rounds' => 1]));
        $this->assertSame('bcrypt', password_get_info($value)['algoName']);
        $this->assertGreaterThanOrEqual(12, password_get_info($value)['options']['cost']);
        $this->assertTrue($this->hashManager->isHashed($value));
        $this->assertTrue($hasher->isAcceptable($value));
        $this->assertFalse($hasher->isAcceptable('password'));
        $this->assertFalse($hasher->isAcceptable('$2y$17$1iPpw8cxiw6.ijzD2Ry1mOvBMM2kPu6wayaIXWLMG5fhFX5ejCEa6'));
        $this->assertFalse($hasher->isAcceptable('$argon2i$v=19$m=65536,t=4,p=1$eE4vbkhJTm54M0k4OU1LTw$C9JCrLeNkNHI1jWx3pBqpK2bTgFrtcVcIfARjCN0218'));
    }

    public function testBasicArgon2iHashing()
    {
        $hasher = new ArgonHasher;
        $value = $hasher->make('password');
        $this->assertNotSame('password', $value);
        $this->assertTrue($hasher->check('password', $value));
        $this->assertFalse($hasher->needsRehash($value));
        $this->assertTrue($hasher->needsRehash($value, ['threads' => 1]));
        $this->assertSame('argon2i', password_get_info($value)['algoName']);
        $this->assertTrue($this->hashManager->isHashed($value));
        $this->assertTrue($hasher->isAcceptable($value));
        $this->assertTrue($hasher->isAcceptable('$argon2i$v=19$m=4194304,t=4,p=16$c01ieWxxZWozSmtHTzd5Vw$y9hJhd9Ip28ZFbh4BEVpPYSA6n017UIBdPcuTVna4hw'));
        $this->assertFalse($hasher->isAcceptable('password'));
        $this->assertFalse($hasher->isAcceptable('$argon2i$v=19$m=4194304,t=4,p=8$Ri5lRGt5VFMvMEtiLkYxQg$sPuFc8V0SKB1gmOJXmqcXscTZ8Awdkihf7m0Y/bskSg'));
        $this->assertFalse($hasher->isAcceptable('$argon2i$v=19$m=8388608,t=4,p=32$Z0JUVVFTMTBVRnZlRHhldQ$sQrSwO1zcTFOseS56GZOd27SR9c05YUXPK7Np+gJpv4'));
        $this->assertFalse($hasher->isAcceptable('$2y$10$PCXl4nmz2z8vckcBFi2AQObDvYOIlNa99REfp0dQN/Hq7Lc1wA5qC'));
    }

    public function testBasicArgon2idHashing()
    {
        $hasher = new Argon2IdHasher;
        $value = $hasher->make('password');
        $this->assertNotSame('password', $value);
        $this->assertTrue($hasher->check('password', $value));
        $this->assertFalse($hasher->needsRehash($value));
        $this->assertTrue($hasher->needsRehash($value, ['threads' => 1]));
        $this->assertSame('argon2id', password_get_info($value)['algoName']);
        $this->assertTrue($this->hashManager->isHashed($value));
        $this->assertTrue($hasher->isAcceptable($value));
        $this->assertTrue($hasher->isAcceptable('$argon2id$v=19$m=4194304,t=4,p=16$WmJySGpROWJuMUJxZXQ5Rw$u96pRIoI4xsj+OfFoluc+iEng3jkDfuTFDIJOYbRml0'));
        $this->assertFalse($hasher->isAcceptable('password'));
        $this->assertFalse($hasher->isAcceptable('$argon2id$v=19$m=4194304,t=4,p=8$VmZWVE5Uc2xDbklQVlhBWA$59KcqVqTfDt4WjoFIQkFIuXQEZBuRN7+G/YR7BDb9i8'));
        $this->assertFalse($hasher->isAcceptable('$argon2id$v=19$m=8388608,t=4,p=32$dVFMcDB4WWkvRU41bGtDMQ$q4Y/26s5RVLn3tInzMgh/jUKeoOj/BXINARKQsvvhC4'));
        $this->assertFalse($hasher->isAcceptable('$2y$10$PCXl4nmz2z8vckcBFi2AQObDvYOIlNa99REfp0dQN/Hq7Lc1wA5qC'));
    }

    /**
     * @depends testBasicBcryptHashing
     */
    public function testBasicBcryptVerification()
    {
        $this->expectException(RuntimeException::class);

        $argonHasher = new ArgonHasher(['verify' => true]);
        $argonHashed = $argonHasher->make('password');
        (new BcryptHasher(['verify' => true]))->check('password', $argonHashed);
    }

    /**
     * @depends testBasicArgon2iHashing
     */
    public function testBasicArgon2iVerification()
    {
        $this->expectException(RuntimeException::class);

        $bcryptHasher = new BcryptHasher(['verify' => true]);
        $bcryptHashed = $bcryptHasher->make('password');
        (new ArgonHasher(['verify' => true]))->check('password', $bcryptHashed);
    }

    /**
     * @depends testBasicArgon2idHashing
     */
    public function testBasicArgon2idVerification()
    {
        $this->expectException(RuntimeException::class);

        $bcryptHasher = new BcryptHasher(['verify' => true]);
        $bcryptHashed = $bcryptHasher->make('password');
        (new Argon2IdHasher(['verify' => true]))->check('password', $bcryptHashed);
    }

    public function testIsHashedWithNonHashedValue()
    {
        $this->assertFalse($this->hashManager->isHashed('foo'));
    }
}
