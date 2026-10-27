import re
import json
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator, validator
from typing import List, Optional

RULE_CONTENT_REGEXP = re.compile(r'^(?=.{1,128}\b)[\w\-/.:,() ]+$')
RULESET_NAME_REGEXP = re.compile(r'^(?=.{1,32}\b)[\w]+$')
PROXY_NAME_REGEXP = re.compile(r'^(?=.{1,64}\b)[^\'"]+$')
PROXY_TAG_REGEXP = re.compile(r'^(?=.{1,64}\b)[\w\-.:@#]+$')
PROXY_INBOUND_REGEXP = re.compile(r'^(?=.{1,64}\b)[\w -]+$')
PROXY_PORT_REGEXP = re.compile(r'^(?=.{1,11}\b)[0-9:]+$')
PROXY_SERVER_REGEXP = re.compile(r'^(?=.{1,64}\b)[\w\-./]+$')
PROXY_GROUP_PROXIES_REGEXP = re.compile(r'^(?=.{1,512})[\w,#\.]+$')

def value_error(err: str, message: str):
    return ValueError(json.dumps({"err": err, "message": message}))

class ClashSetting(BaseModel):
    name: str
    content: str

class ClashSettingCreate(ClashSetting):
    pass

class ClashSettingResponse(ClashSetting):
    model_config = ConfigDict(from_attributes=True)

class ClashSettingsResponse(BaseModel):
    data: List[ClashSettingResponse]
    total: int

class ClashProxy(BaseModel):
    name: str
    server: str
    builtin: Optional[bool] = False
    tag: str
    port: str
    inbound: str
    settings: dict

    @field_validator('name', check_fields=False)
    def validate_name(cls, v):
        if not PROXY_NAME_REGEXP.match(v):
            raise value_error('InvalidProxyName', 'name not accept quotes')
        return v
    
    @field_validator('tag', check_fields=False)
    def validate_tag(cls, v):
        if not PROXY_TAG_REGEXP.match(v):
            raise value_error('InvalidProxyTag', 'tag only accept "A-Za-z0-9_:-.@#"')
        return v
    
    @field_validator('port', check_fields=False)
    def validate_port(cls, v):
        if not PROXY_PORT_REGEXP.match(v):
            raise value_error('InvalidProxyPort', 'port only accept "0-9:"')
        return v
    
    @field_validator('server', check_fields=False)
    def validate_server(cls, v):
        if ":" in v:
            from ipaddress import ip_address
            try:
                return str(ip_address(v.strip("[]")))
            except ValueError:
                raise value_error('InvalidProxyServer', 'Invalid IP address')
        if not PROXY_SERVER_REGEXP.match(v):
            raise value_error('InvalidProxyServer', 'server only accept "A-Za-z0-9/-._"')
        return v
    
    @field_validator('inbound', check_fields=False)
    def validate_inbound(cls, v):
        if not PROXY_INBOUND_REGEXP.match(v):
            if not v:
                raise value_error('NoProxyInbound', 'no proxies selected')
            else:
                raise ValueError('inbound only accept "A-Za-z0-9 "')
        return v

    @model_validator(mode="after")
    def validate_hysteria2(self):
        from app import xray
        from app.models.proxy import Hysteria2Options
        inbound = xray.config.inbounds_by_tag.get(self.inbound, {})
        if inbound.get("protocol") == "hysteria2":
            ports = self.port.split(":")
            if len(ports) > 2 or not all(p.isdigit() and 1 <= int(p) <= 65535 for p in ports):
                raise ValueError("Hysteria 2 ports must be between 1 and 65535")
            if len(ports) == 2 and int(ports[0]) > int(ports[1]):
                raise ValueError("Port range must be ascending")
            overrides = self.settings.get("hysteria2", {})
            options = Hysteria2Options.model_validate({**inbound["hysteria2"], **overrides})
            self.settings = {**self.settings, "hysteria2": options.model_dump(include=set(overrides))}
        return self


class ClashProxyCreate(ClashProxy):
    pass

class ClashProxyBriefResponse(BaseModel):
    id: str
    name: str
    server: str
    tag: str
    builtin: bool

class ClashProxyBriefsResponse(BaseModel):
    data: List[ClashProxyBriefResponse]

class ClashProxyResponse(ClashProxy):
    id: int
    model_config = ConfigDict(from_attributes=True)

class ClashProxiesResponse(BaseModel):
    data: List[ClashProxyResponse]
    total: int

class ClashProxyGroup(BaseModel):
    name: str
    tag: str
    type: str
    builtin: bool
    proxies: str
    settings: dict

    @field_validator('name', check_fields=False)
    def validate_name(cls, v):
        if not PROXY_NAME_REGEXP.match(v):
            raise value_error('InvalidProxyName', 'name not accept quotes')
        return v
    
    @field_validator('tag', check_fields=False)
    def validate_tag(cls, v):
        if not PROXY_TAG_REGEXP.match(v):
            raise value_error('InvalidProxyTag', 'tag only accept "A-Za-z0-9_:-.@#"')
        return v
    
    @field_validator('proxies', check_fields=False)
    def validate_proxies(cls, v: str):
        if not PROXY_GROUP_PROXIES_REGEXP.match(v):
            if not v or v.count() == 0:
                raise value_error('NoProxy', 'no proxies selected')
            else:
                raise ValueError('proxies only accept "0-9,"')
        return v

class ClashProxyGroupCreate(ClashProxyGroup):
    pass

class ClashProxyGroupResponse(ClashProxyGroup):
    id: int
    model_config = ConfigDict(from_attributes=True)

class ClashProxyGroupsResponse(BaseModel):
    data: List[ClashProxyGroupResponse]
    total: int

class ClashLink(BaseModel):
    name: str
    tag: str
    prefix: str
    url: str
    modified_at: Optional[datetime] = None

    @field_validator('tag', mode='before')
    def validate_tag(cls, v):
        if not PROXY_TAG_REGEXP.match(v):
            raise value_error('InvalidProxyTag', 'tag only accept "A-Za-z0-9_:-.@#"')
        return v
    
class ClashLinkCreate(ClashLink):
    pass

class ClashLinkResponse(ClashLink):
    id: int
    model_config = ConfigDict(from_attributes=True)

class ClashLinksResponse(BaseModel):
    data: List[ClashLinkResponse]
    total: int

class ClashProxyTagResponse(BaseModel):
    tag: str
    servers: List[str]

class ClashProxyTagsResponse(BaseModel):
    data: List[ClashProxyTagResponse]

class ClashProxyInboundResponse(BaseModel):
    settings: dict = Field(default_factory=dict)
    name: str
    type: str
    server: str
    security: str
    network: str
    port: int
    servername: str

class ClashProxyInboundsResponse(BaseModel):
    data: List[ClashProxyInboundResponse]

class ClashRule(BaseModel):
    type: str
    content: str
    option: str
    policy: str
    ruleset: str
    priority: int

    @field_validator('content', check_fields=False)
    def validate_content(cls, v):
        if not RULE_CONTENT_REGEXP.match(v):
            raise value_error('InvalidRuleContent', 'content only accept "A-Za-z0-9_-/.:,()"')
        return v
    
class ClashRuleCreate(ClashRule):
    ruleset_id: Optional[int] = 0

class ClashRuleResponse(ClashRule):
    id: int
    model_config = ConfigDict(from_attributes=True)

    @field_validator('ruleset', mode='before', check_fields=False)
    def validate_ruleset(cls, v):
        return v.name

class ClashRulesResponse(BaseModel):
    data: List[ClashRuleResponse]
    total: int

class ClashRuleset(BaseModel):
    name: str
    builtin: bool
    policy: str
    settings: dict

    @field_validator('name', check_fields=False)
    def validate_name(cls, v):
        if not RULESET_NAME_REGEXP.match(v):
            raise value_error('InvalidRulesetName', 'name only accept "a-zA-Z0-9_"')
        return v

class ClashRulesetCreate(ClashRuleset):
    pass

class ClashRulesetResponse(ClashRuleset):
    id: int
    model_config = ConfigDict(from_attributes=True)

class ClashRulesetsResponse(BaseModel):
    data: List[ClashRulesetResponse]
