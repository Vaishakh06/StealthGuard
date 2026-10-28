import ipaddress


class TargetValidationError(ValueError):
    """Raised when a mitigation target is invalid or outside the lab."""


class TargetValidator:
    """
    Validates mitigation targets before any enforcement action.

    The allowed networks are configurable so that Person 1 can later
    provide the actual Docker lab subnets without changing controller logic.
    """

    def __init__(
        self,
        allowed_source_networks=None,
        allowed_destination_networks=None,
    ):
        self.allowed_source_networks = [
            ipaddress.ip_network(net)
            for net in (allowed_source_networks or [])
        ]

        self.allowed_destination_networks = [
            ipaddress.ip_network(net)
            for net in (allowed_destination_networks or [])
        ]

    @staticmethod
    def validate_ip(ip):
        try:
            return ipaddress.ip_address(ip)
        except ValueError as exc:
            raise TargetValidationError(
                f"Invalid IP address: {ip}"
            ) from exc

    @staticmethod
    def validate_port(port):
        if not isinstance(port, int):
            raise TargetValidationError(
                f"Port must be an integer: {port}"
            )

        if not 1 <= port <= 65535:
            raise TargetValidationError(
                f"Port out of range: {port}"
            )

        return port

    @staticmethod
    def _in_allowed_networks(ip, networks):
        if not networks:
            return False

        return any(ip in network for network in networks)

    def validate_source(self, source_ip):
        ip = self.validate_ip(source_ip)

        if not self._in_allowed_networks(
            ip,
            self.allowed_source_networks,
        ):
            raise TargetValidationError(
                f"Source IP is outside allowed lab networks: {source_ip}"
            )

        return True

    def validate_destination(self, destination_ip):
        ip = self.validate_ip(destination_ip)

        if not self._in_allowed_networks(
            ip,
            self.allowed_destination_networks,
        ):
            raise TargetValidationError(
                f"Destination IP is outside allowed lab networks: "
                f"{destination_ip}"
            )

        return True

    def validate(
        self,
        source_ip,
        destination_ip,
        destination_port,
    ):
        self.validate_source(source_ip)
        self.validate_destination(destination_ip)
        self.validate_port(destination_port)

        return True