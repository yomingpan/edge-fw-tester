from pathlib import Path
from typing import Optional, List

from pydantic import BaseModel, Field, ValidationError, field_validator
import yaml


class L7Check(BaseModel):
    type: str = Field(..., description="http | grpc | none")
    path: Optional[str] = None  # for http
    timeout: float = 3.0


class Flow(BaseModel):
    name: str
    host: str
    port: int
    proto: str = Field("tcp", pattern="^(tcp|udp)$")
    l7_check: Optional[L7Check] = None

    @field_validator("port")
    @classmethod
    def port_range(cls, v: int):
        if not (1 <= v <= 65535):
            raise ValueError("port must be 1-65535")
        return v


def load_flows(path) -> List[Flow]:
    try:
        file_content = Path(path).read_text()
    except FileNotFoundError:
        raise RuntimeError("Config file not found: {}".format(path))
    except PermissionError:
        raise RuntimeError("Permission denied for config file: {}".format(path))

    data = yaml.safe_load(file_content)
    if data is None:
        data = []
    flows = []
    for item in data:
        ports = item["port"]
        if isinstance(ports, int):
            ports = [ports]
        elif isinstance(ports, str):
            ports = [int(p.strip()) for p in ports.split(",") if p.strip()]
        else:
            raise ValueError(f"Invalid port value: {ports}")
        for p in ports:
            flow_item = item.copy()
            flow_item["port"] = p
            # 若多 port，自動補上 port 編號於 name
            if len(ports) > 1:
                flow_item["name"] = f"{item['name']}-{p}"
            flows.append(Flow(**flow_item))
    return flows
