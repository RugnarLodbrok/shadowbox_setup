import os
import subprocess
from base64 import b64encode
from functools import cached_property
from pathlib import Path
from typing import Self

import requests
import yaml
from pydantic import BaseModel
from pydantic_settings import BaseSettings


class Config(BaseSettings):
    HOME: Path = Path('/opt/outline')
    API_PORT: int = 9001
    IMAGE: str = 'quay.io/outline/shadowbox:stable'
    HOSTNAME_RESOLVERS: list[str] = ['https://ipinfo.io/ip',
                                     'https://icanhazip.com/',
                                     'https://domains.google.com/checkip', ]
    PUBLIC_IP: str | None = None

    @cached_property
    def public_ip(self) -> str:
        if self.PUBLIC_IP:
            return self.PUBLIC_IP
        for url in self.HOSTNAME_RESOLVERS:
            return _shell('fetch', '--ipv4', url)  # todo: use requests?

    @property
    def state_dir(self) -> Path:
        return self.HOME / 'persistent_state'


class ServerConfig(BaseModel):
    portForNewAccessKeys: int = 9002
    hostname: str


class UserConfig(BaseModel):
    api_prefix: str
    public_ip: str
    cert_fingerprint: str
    cert_name: str = 'shadowbox-selfsigned'

    @classmethod
    def load(cls, path=Path('user_config.yml')) -> Self:
        return cls.model_validate(yaml.safe_load(path.read_bytes()))

    def save(self, path=Path('user_config.yml')) -> None:
        path.write_text(yaml.safe_dump(self.model_dump()))

    @classmethod
    def generate(cls, config: Config) -> Self:
        def _generate_api_key() -> str:
            return b64encode(os.urandom(16)).decode()

        def _get_public_ip() -> str:
            if config.PUBLIC_IP:
                return config.PUBLIC_IP
            for url in config.HOSTNAME_RESOLVERS:
                try:
                    r = requests.get(url, timeout=10)
                except requests.ConnectionError:
                    continue
                if r.ok:
                    return r.text.strip()

                # return _shell('fetch', '--ipv4', url)  # todo: use requests?

        return cls(
            public_ip=_get_public_ip(),
            api_prefix=_generate_api_key(),
            cert_fingerprint='',
        )

    @property
    def cert_key_file(self) -> Path:
        return Path(f'{self.cert_name}.key').absolute()

    @property
    def cert_file(self) -> Path:
        return Path(f'{self.cert_name}.crt').absolute()

    def generate_keys(self):
        if self.cert_file.exists() or self.cert_key_file.exists():
            raise InstallationExists(f'cert already exists: {self.cert_file}')

        _shell(
            'openssl', 'req',
            '-x509', '-nodes', '-days', '36500', '-newkey', 'rsa:4096',
            '-subj', f"/CN={self.public_ip}",
            '-keyout', f'{self.cert_key_file}',
            '-out', f'{self.cert_file}'
        )
        self.cert_fingerprint = _shell(
            'openssl', 'x509', '-in', f'{self.cert_file}', '-noout', '-sha256', '-fingerprint'
        ).strip()


class InstallationExists(Exception):
    pass


def _shell(*args: str) -> str:
    return subprocess.run(args, capture_output=True, check=True).stdout.decode()


def check_machine_type():
    machine_type = _shell('unamme', '-m')
    if machine_type != "x86_64":
        raise AssertionError(f"Unsupported machine type: {machine_type}")


def check_docker():
    pass


def checks():
    check_machine_type()
    check_docker()


def main():
    config = Config()

    checks()

    if not config.state_dir.exists():
        config.HOME.mkdir(mode=0o700, parents=True)
        subprocess.check_call(['chmod', 'u+s,ug+rwx,o-rwx', config.HOME])
        config.state_dir.mkdir(exist_ok=True)
        subprocess.check_call(['chmod', 'ug+rwx,g+s,o-rwx', config.state_dir])
    os.chdir(config.state_dir)

    try:
        uc = UserConfig.load()
    except FileNotFoundError:
        uc = UserConfig.generate(config)
        uc.generate_keys()
        uc.save()


if __name__ == '__main__':
    # config = Config()
    # main()
    uc = UserConfig.load()
