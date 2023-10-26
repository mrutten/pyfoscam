"""
A module to manage Foscam FI9936P cameras
"""

try:
    from urllib import urlopen
except ImportError:
    from urllib.request import urlopen
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode
try:
    from urllib import unquote
except ImportError:
    from urllib.parse import unquote

import xml.etree.ElementTree as ET
from threading import Thread

try:
    import ssl

    ssl_enabled = True
except ImportError:
    ssl_enabled = False

from collections import OrderedDict

# Foscam error codes
FOSCAM_SUCCESS = 0
ERROR_FOSCAM_FORMAT = -1
ERROR_FOSCAM_AUTH = -2
ERROR_FOSCAM_CMD = -3  # Access deny. May the cmd is not supported.
ERROR_FOSCAM_EXE = -4  # CGI execute fail.
ERROR_FOSCAM_TIMEOUT = -5
ERROR_FOSCAM_UNKNOWN = -7  # -6 and -8 are reserved.
ERROR_FOSCAM_UNAVAILABLE = -8  # Disconnected or not a cam.


class FoscamError(Exception):
    def __init__(self, code):
        super(FoscamError, self).__init__()
        self.code = int(code)

    def __str__(self):
        return f"ErrorCode: {self.code}"


class FoscamCamera(object):
    """A python implementation for foscam FI9936P"""

    def __init__(self, host, port, usr, pwd, daemon=False, ssl=None, verbose=False):
        """
        If daemon is True, the command will be sent unblocked.
        """
        self.host = host
        self.port = port
        self.usr = usr
        self.pwd = pwd
        self.daemon = daemon
        self.verbose = verbose
        self.ssl = ssl
        if ssl_enabled:
            if port == 443 and ssl is None:
                self.ssl = True
        if self.ssl is None:
            self.ssl = False

    @property
    def url(self):
        _url = f"{self.host}:{self.port}"
        return _url

    def send_command(self, cmd, params=None, raw=False):
        """
        Send command to foscam camera
        """
        paramstr = ""
        if params:
            paramstr = urlencode(params)
            paramstr = "&" + paramstr if paramstr else ""
        cmdurl = f"http://{self.url}/cgi-bin/CGIProxy.fcgi?usr={self.usr}&pwd={self.pwd}&cmd={cmd}{paramstr}"
        if self.ssl and ssl_enabled:
            cmdurl = cmdurl.replace("http:", "https:")

        # Parse parameters from response string.
        if self.verbose:
            print(f"Send Foscam command: {cmdurl}")
        try:
            raw_string = ""
            if self.ssl and ssl_enabled:
                gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # disable cert
                raw_string = urlopen(cmdurl, context=gcontext, timeout=5).read()
            else:
                raw_string = urlopen(cmdurl, timeout=5).read()
            if raw:
                if self.verbose:
                    print(f"Returning raw Foscam response: len={len(raw_string)}")
                return FOSCAM_SUCCESS, raw_string
            root = ET.fromstring(raw_string)
        except:
            if self.verbose:
                print(f"Foscam exception: {raw_string}")
            return ERROR_FOSCAM_UNAVAILABLE, None
        code = ERROR_FOSCAM_UNKNOWN
        params = OrderedDict()
        for child in root.iter():
            if child.tag == "result":
                code = int(child.text)

            elif child.tag != "CGI_Result":
                params[child.tag] = (
                    unquote(child.text) if child.text is not None else None
                )

        if self.verbose:
            print(f"Received Foscam response: {code}, {params}")
        return code, params

    def execute_command(self, cmd, params=None, callback=None, raw=False):
        """
        Execute a command and return a parsed response.
        """

        def execute_with_callbacks(cmd, params=None, callback=None, raw=False):
            code, params = self.send_command(cmd, params, raw)
            if callback:
                callback(code, params)
            return code, params

        if self.daemon:
            t = Thread(
                target=execute_with_callbacks,
                args=(cmd,),
                kwargs={"params": params, "callback": callback, "raw": raw},
            )
            t.daemon = True
            t.start()
        else:
            return execute_with_callbacks(cmd, params, callback, raw)

    # *************** Network ******************

    def get_ip_info(self, callback=None):
        """
        Function: Get IP Info
        Privilege: admin
        Params: None
        Returns:
            isDHCP: 0(False), 1(True)
            ip: ip address
            gate: gateway
            mask: subnet mask
            dns1: first DNS server
            dns2: second DNS server
        """
        return self.execute_command("getIPInfo", callback=callback)

    def set_ip_info(
        self, is_dhcp, ip="", gate="", mask="", dns1="", dns2="", callback=None
    ):
        """
        Function Set IP info
        Privilege: admin
        Params:
            isDHCP: 0(False), 1(True)
            ip: ip address
            gate: gateway
            mask: subnet mask
            dns1: first DNS server
            dns2: second DNS server
        Returns: None
        Note: System will reboot automatically after calling this CGI command.
        """
        params = {
            "isDHCP": is_dhcp,
            "ip": ip,
            "gate": gate,
            "mask": mask,
            "dns1": dns1,
            "dns2": dns2,
        }

        return self.execute_command("setIpInfo", params, callback=callback)

    def refresh_wifi_list(self, callback=None):
        """
        Function: Scan APs
        Privilege: admin
        Params: None
        Returns: None
        Note: This operation may take a while, about 20s or more,
              other operations on this device will be blocked during that period.
        """
        return self.execute_command("refreshWifiList", callback=callback)

    def get_wifi_list(self, startno=0, callback=None):
        """
        Function: Get APs after completing refreshWifiList
        Privilege: admin
        Params:
            StartNo: Start at N in the AP list
        Returns:
            totalCnt: Total count of APs
            curCnt: Current AP count
            apN: Detailed info of AP N (SSID+MAC+quality+isEncrypted+encrypType)
        Note: Only 10 APs will be returned at one time
        """
        params = {"startNo": startno}
        return self.execute_command("getWifiList", params, callback=callback)

    def set_wifi_setting(
        self,
        ssid,
        psk,
        isenable,
        isusewifi,
        nettype,
        encryptype,
        authmode,
        keyformat,
        defaultkey,
        key1="",
        key2="",
        key3="",
        key4="",
        key1len=64,
        key2len=64,
        key3len=64,
        key4len=64,
        callback=None,
    ):
        """
        Function: Set wifi config
        Privilege: admin
        Params:
            isEnable: Enable state
            isUseWifi: Use WiFi or not
            ssid: AP name
            netType: 0(Infra net), 1(Ad-hoc, not supported)
            encryptType: 0(Open mode), 1(WEP), 2(WPA), 3(WPA2), 4(WPA/WPA2)
            psk: WPA/WPA2 PSK
            authMode: 0(Open mode), 1(Shared key), 2(Auto mode)
            keyFormat: 0(ASIC), 1(Hex)
            defaultKey: 1-4
            key1Len: 64 or 128
            key2Len: 64 or 128
            key3Len: 64 or 128
            key4Len: 64 or 128
            isNewFormat: 1(encrypt password by using ASCCI conversion, separated by commas)
        Returns: None
        Note: Camera will not connect to the AP unless the UTP cable is disconnected.
        """
        params = {
            "isEnable": isenable,
            "isUseWifi": isusewifi,
            "ssid": ssid,
            "netType": nettype,
            "encryptType": encryptype,
            "psk": psk,
            "authMode": authmode,
            "keyFormat": keyformat,
            "defaultKey": defaultkey,
            "key1": key1,
            "key2": key2,
            "key3": key3,
            "key4": key4,
            "key1Len": key1len,
            "key2Len": key2len,
            "key3Len": key3len,
            "key4Len": key4len,
        }
        return self.execute_command("setWifiSetting", params, callback=callback)

    def get_wifi_config(self, callback=None):
        """
        Function: Get WiFi config
        Privilege: admin
        Params: None
        Returns:
            isEnable: Enable state
            isUseWifi: Use WiFi or not
            isConnected: Connected state
            connectedAP: Connected AP
            ssid: AP name
            encryptType: 0(Open mode), 1(WEP), 2(WPA), 3(WPA2), 4(WPA/WPA2)
            psk: WPA/WPA2 PSK
            authMode: 0(Open mode), 1(Shared key), 2(Auto mode)
            keyFormat: 0(ASIC), 1(Hex)
            defaultKey: 1-4
            key1Len: 64 or 128
            key2Len: 64 or 128
            key3Len: 64 or 128
            key4Len: 64 or 128
        Note: Camera will not connect to the AP unless the UTP cable is disconnected.
        """
        return self.execute_command("getWifiConfig", callback=callback)

    def get_port_info(self, callback=None):
        """
        Function: Get ports of the camera
        Privilege: admin
        Params: None
        Returns:
            webPort: HTTP port(default value is 88)
            httpsPort: HTTPS port(default value is 443)
            mediaPort: Media port(default value is 88)
            onvifPort: Open Network Video Interface Form port(default value is 888)
            rtspPort: Real-Time Streaming Protocol port(default value is 88)
        Note: Can be called without usr or pwd section.
              onvifPort param is only for onvif-capable camera.
        """
        return self.execute_command("getPortInfo", callback=callback)

    def set_port_info(
        self, webport, mediaport, httpsport, onvifport, rtspport, callback=None
    ):
        """
        Function: Set ports of camera
        Privilege: admin
        Params:
            webPort: HTTP port(default value is 88)
            httpsPort: HTTPS port(default valie is 443)
            mediaPort: Media port(default value is 88)
            onvifPort: Open Network Video Interface Form port(default value is 888)
            rtspPort: Real-Time Streaming Protocol port(default value is 88)
        Returns: None
        Note: New login needed after this CGI command.
        """
        params = {
            "webPort": webport,
            "mediaPort": mediaport,
            "httpsPort": httpsport,
            "onvifPort": onvifport,
            "rtspPort": rtspport,
        }
        return self.execute_command("setPortInfo", params, callback=callback)

    def get_upnp_config(self, callback=None):
        """
        Function: Get UPnP config
        Privilege: admin
        Params: None
        Returns:
            isEnable: is Universal Plug and Play enabled
        """
        return self.execute_command("getUPnPConfig", callback=callback)

    def set_upnp_config(self, isenable, callback=None):
        """
        Function: Set UPnP config
        Privilege: admin
        Params:
            isEnable: is Universal Plug and Play enabled
        Returns: None
        """
        params = {"isEnable": isenable}
        return self.execute_command("setUPnPConfig", params, callback=callback)

    def get_ddns_config(self, callback=None):
        """
        Function: Get DDNS config
        Privilege: admin
        Params: None
        Returns:
            isEnable: is DDNS update enabled
            hostName: DDNS domain
            ddnsServer: 0(Factory DDNS), 1(Oray), 2(3322), 3(no-ip), 4(dyndns)
            user: Username
            password: Password
            factoryDDNS: Factory DDNS
        """
        return self.execute_command("getDDNSConfig", callback=callback)

    def set_ddns_config(
        self, isenable, hostname, ddnsserver, user, password, callback=None
    ):
        """
        Function: Set DDNS config
        Privilege: admin
        Params:
            isEnable: is DDNS update enabled
            hostName: DDNS domain
            ddnsServer: 0(Factory DDNS), 1(Oray), 2(3322), 3(no-ip), 4(dyndns)
            user: Username
            password: Password
        Returns: None
        Note: This command can only be used by the third party DDNS
        """
        params = {
            "isEnable": isenable,
            "hostName": hostname,
            "ddnsServer": ddnsserver,
            "user": user,
            "password": password,
        }
        return self.execute_command("setDDNSConfig", params, callback=callback)

    def get_ftp_config(self, callback=None):
        """
        Function: Get FTP config
        Privilege: admin
        Params: None
        Returns:
            ftpAddr: FTP server address
            ftpPort: FTP port(default value is 21)
            mode: 0(PASV mode), 1(PORT mode)
            userName: Username
            password: password
        """
        return self.execute_command("getFtpConfig", callback=callback)

    def set_ftp_config(self, ftpaddr, ftpport, mode, username, password, callback=None):
        """
        Function: Set FTP config
        Privilege: admin
        Params:
            ftpAddr: FTP server address
            ftpPort: FTP port(default value is 21)
            mode: 0(PASV mode), 1(PORT mode)
            userName: Username
            password: password
        Returns: None
        """
        params = {
            "ftpAddr": ftpaddr,
            "ftpPort": ftpport,
            "mode": mode,
            "userName": username,
            "password": password,
        }
        return self.execute_command("setFtpConfig", params, callback=callback)

    def test_ftp_server(
        self, ftpaddr, ftpport, mode, ftpusername, ftppassword, callback=None
    ):
        """
        Function: Test FTP server
        Privilege: admin
        Params:
            ftpAddr: FTP server address(ftp://<ip-address>/optional-subdirectory)
            ftpPort: FTP port(default value is 21)
            mode: 0(PASV mode), 1(PORT mode)
            ftpuserName: Username
            ftppassword: password
        """
        params = {
            "ftpAddr": ftpaddr,
            "ftpPort": ftpport,
            "mode": mode,
            "ftpuserName": ftpusername,
            "ftppassword": ftppassword,
        }
        return self.execute_command("testFtpServer", params, callback=callback)

    def get_smtp_config(self, callback=None):
        """
        Function: Get mail config
        Privilege: admin
        Params: None
        Returns:
            isEnable: is SMTP enabled
            server: SMTP server address
            port: SMTP port
            isNeedAuth: Need auth user account or not
            tls: 0(None), 1(TLS), 2(STARTTLS)
            user: Username
            password: Password
            sender: Sender address
            receiver: Use "," between 2 senders, e.g. foo@example.com,bar@example.com
        """
        return self.execute_command("getSMTPConfig", callback=callback)

    def set_smtp_config(
        self,
        isenable,
        server,
        port,
        isneedauth,
        tls,
        user,
        password,
        sender,
        receiver,
        callback=None,
    ):
        """
        Function: Set mail config
        Privilege: admin
        Params:
            isEnable: is SMTP enabled
            server: SMTP server address
            port: SMTP port
            isNeedAuth: Need auth user account or not
            tls: 0(None), 1(TLS), 2(STARTTLS)
            user: Username
            password: Password
            sender: Sender address
            receiver: Use "," between 2 senders, e.g. foo@example.com,bar@example.com
        Returns: None
        """
        params = {
            "isEnable": isenable,
            "server": server,
            "port": port,
            "isNeedAuth": isneedauth,
            "tls": tls,
            "user": user,
            "password": password,
            "sender": sender,
            "receiver": receiver,
        }
        return self.execute_command("setSMTPConfig", params, callback=callback)

    def smtp_test(
        self, smtpserver, port, isneedauth, tls, user, password, sender, callback=None
    ):
        """
        Function: Test mail setting
        Privilege: admin
        Params:
            smtpServer: SMTP server address
            port: SMTP port
            isNeedAuth: Need auth user account or not
            tls: 0(None), 1(TLS), 2(STARTTLS)
            user: Username
            password: Password
            sender: Sender address
        Returns:
            testResult: 0(Success), -1(Fail)
        Note: Must be preceded by setSMTPConfig.
              A mail will be sent to all receivers configured by setSMTPConfig.
        """
        params = {
            "smtpServer": smtpserver,
            "port": port,
            "isNeedAuth": isneedauth,
            "tls": tls,
            "user": user,
            "password": password,
            "sender": sender,
        }
        return self.execute_command("smtpTest", params, callback=callback)

    def get_p2p_enable(self, callback=None):
        """
        Function: Get P2P status
        Privilege: admin
        Params: None
        Returns:
            enable: 0(disabled), 1(enabled)
        """
        return self.execute_command("getP2PEnable", callback=callback)

    def set_p2p_enable(self, enable, callback=None):
        """
        Function: Set P2P status
        Privilege: admin
        Params: None
        Returns:
            enable: 0(Disable), 1(Enable)
        """
        params = {"enable": enable}
        return self.execute_command("setP2PEnable", params, callback=callback)

    def get_p2p_port(self, callback=None):
        """
        Function: Get P2P port
        Privilege: admin
        Params: None
        Returns:
            port: P2P port number
        """
        return self.execute_command("getP2PPort", callback=callback)

    def set_p2p_port(self, port, callback=None):
        """
        Function: Set P2P port
        Privilege: admin
        Params:
            port: P2P port number
        Returns: None
        """
        params = {
            "port": port,
        }
        return self.execute_command("setP2PPort", params, callback=callback)

    def get_p2p_info(self, callback=None):
        """
        Function: Get P2P UID
        Privilege: admin
        Params: None
        Returns:
            uid: P2P UID
        """
        return self.execute_command("getP2PInfo", callback=callback)

    def get_pppoe_config(self, callback=None):
        """
        Function: Get PPPoE config
        Privilege: admin
        Params: None
        Returns:
            isEnable: is PPPoE function enabled
            userName: Username
            password: Password
        """
        return self.execute_command("getPPPoEConfig", callback=callback)

    def set_pppoe_config(self, isenable, username, password, callback=None):
        """
        Function: Set PPPoE config
        Privilege: admin
        Params:
            isEnable: is PPPoE function enabled
            userName: Username
            password: Password
        Returns: None
        """
        params = {
            "isEnable": isenable,
            "userName": username,
            "password": password,
        }
        return self.execute_command("setPPPoEConfig", params, callback=callback)

    # *************** AV Settings  ******************

    def get_sub_video_stream_type(self, callback=None):
        """
        Get the stream type of sub stream.
        """
        return self.execute_command("getSubVideoStreamType", callback=callback)

    def set_sub_video_stream_type(self, format, callback=None):
        """
        Set the stream fromat of sub stream.
        Supported format: (1) H264 : 0
                          (2) MotionJpeg 1
        """
        params = {"format": format}
        return self.execute_command("setSubVideoStreamType", params, callback=callback)

    def set_sub_stream_format(self, format, callback=None):
        """
        Set the stream fromat of sub stream????
        """
        params = {"format": format}
        return self.execute_command("setSubStreamFormat", params, callback=callback)

    def get_main_video_stream_type(self, callback=None):
        """
        Get the stream type of main stream
        """
        return self.execute_command("getMainVideoStreamType", callback=callback)

    def set_main_video_stream_type(self, streamtype, callback=None):
        """
        Set the stream type of main stream
        """
        params = {"streamType": streamtype}
        return self.execute_command("setMainVideoStreamType", params, callback=callback)

    def get_video_stream_param(self, callback=None):
        """
        Get video stream param
        """
        return self.execute_command("getVideoStreamParam", callback=callback)

    def set_video_stream_param(
        self, streamtype, resolution, bitrate, framerate, gop, isvbr, callback=None
    ):
        """
        Set the video stream param of stream N
        streamtype(0~3): Stream N.
        resolution(0~4): 0 720P,
                         1 VGA(640*480),
                         2 VGA(640*360),
                         3 QVGA(320*240),
                         4 QVGA(320*180).
        bitrate: Bit rate of stream type N(20480~2097152).
        framerate: Frame rate of stream type N.
        GOP: P frames between 1 frame of stream type N.
             The suggest value is: X * framerate.
        isvbr: 0(Not in use currently), 1(In use).
        """
        params = {
            "streamType": streamtype,
            "resolution": resolution,
            "bitRate": bitrate,
            "frameRate": framerate,
            "GOP": gop,
            "isVBR": isvbr,
        }
        return self.execute_command("setVideoStreamParam", params, callback=callback)

    def mirror_video(self, is_mirror, callback=None):
        """
         Mirror video
        ``is_mirror``: 0 not mirror, 1 mirror
        """
        params = {"isMirror": is_mirror}
        return self.execute_command("mirrorVideo", params, callback=callback)

    def flip_video(self, is_flip, callback=None):
        """
        Flip video
        ``is_flip``: 0 Not flip, 1 Flip
        """
        params = {"isFlip": is_flip}
        return self.execute_command("flipVideo", params, callback=callback)

    def get_mirror_and_flip_setting(self, callback=None):
        return self.execute_command("getMirrorAndFlipSetting", None, callback=callback)

    # *************** User account ******************

    def change_user_name(self, usrname, newusrname, callback=None):
        """
        Change user name.
        """
        params = {
            "usrName": usrname,
            "newUsrName": newusrname,
        }
        return self.execute_command("changeUserName", params, callback=callback)

    def change_password(self, usrname, oldpwd, newpwd, callback=None):
        """
        Change password.
        """
        params = {
            "usrName": usrname,
            "oldPwd": oldpwd,
            "newPwd": newpwd,
        }
        return self.execute_command("changePassword", params, callback=callback)

    # *************** Device manage *******************

    def set_system_time(
        self,
        time_source,
        ntp_server,
        date_format,
        time_format,
        time_zone,
        is_dst,
        dst,
        year,
        mon,
        day,
        hour,
        minute,
        sec,
        callback=None,
    ):
        """
        Set system time
        """
        if ntp_server not in [
            "time.nist.gov",
            "time.kriss.re.kr",
            "time.windows.com",
            "time.nuri.net",
            "Auto",
        ]:
            raise ValueError("Unsupported ntpServer")

        params = {
            "timeSource": time_source,
            "ntpServer": ntp_server,
            "dateFormat": date_format,
            "timeFormat": time_format,
            "timeZone": time_zone,
            "isDst": is_dst,
            "dst": dst,
            "year": year,
            "mon": mon,
            "day": day,
            "hour": hour,
            "minute": minute,
            "sec": sec,
        }

        return self.execute_command("setSystemTime", params, callback=callback)

    def get_system_time(self, callback=None):
        """
        Get system time.
        """
        return self.execute_command("getSystemTime", callback=callback)

    def get_dev_name(self, callback=None):
        """
        Get camera name.
        """
        return self.execute_command("getDevName", callback=callback)

    def set_dev_name(self, devname, callback=None):
        """
        Set camera name
        """
        params = {"devName": devname.encode("gbk")}
        return self.execute_command("setDevName", params, callback=callback)

    def get_dev_state(self, callback=None):
        """
        Get all device state
        cmd: getDevState
        return args:
            ......
            record:      0   Not in recording; 1 Recording
            sdState:     0   No sd card; 1 Sd card OK; 2 SD card read only
            sdFreeSpace: Free space of sd card by unit of k
            sdTotalSpace: Total space of sd card by unit of k
            ......
        """
        return self.execute_command("getDevState", callback=callback)

    def get_dev_info(self, callback=None):
        """
        Get camera information
        cmd: getDevInfo
        """
        return self.execute_command("getDevInfo", callback=callback)

    def open_infra_led(self, callback=None):
        """
        Force open infra led
        cmd: openInfraLed
        """
        return self.execute_command("openInfraLed", {}, callback=callback)

    def close_infra_led(self, callback=None):
        """
        Force close infra led
        cmd: closeInfraLed
        """
        return self.execute_command("closeInfraLed", callback=callback)

    def get_infra_led_config(self, callback=None):
        """
        Get Infrared LED configuration
        cmd: getInfraLedConfig
        """
        return self.execute_command("getInfraLedConfig", callback=callback)

    def set_infra_led_config(self, mode, callback=None):
        """
        Set Infrared LED configuration
        cmd: setInfraLedConfig
        mode(0,1): 0=Auto mode, 1=Manual mode
        """
        params = {"mode": mode}
        return self.execute_command("setInfraLedConfig", params, callback=callback)

    def get_product_all_info(self, callback=None):
        """
        Get camera information
        cmd: getProductAllInfo
        """
        return self.execute_command("getProductAllInfo", callback=callback)

    # *************** PTZ Control *******************

    def ptz_move_up(self, callback=None):
        """
        Move up
        """
        return self.execute_command("ptzMoveUp", callback=callback)

    def ptz_move_down(self, callback=None):
        """
        Move down
        """
        return self.execute_command("ptzMoveDown", callback=callback)

    def ptz_move_left(self, callback=None):
        """
        Move left
        """
        return self.execute_command("ptzMoveLeft", callback=callback)

    def ptz_move_right(self, callback=None):
        """
        Move right.
        """
        return self.execute_command("ptzMoveRight", callback=callback)

    def ptz_move_top_left(self, callback=None):
        """
        Move to top left.
        """
        return self.execute_command("ptzMoveTopLeft", callback=callback)

    def ptz_move_top_right(self, callback=None):
        """
        Move to top right.
        """
        return self.execute_command("ptzMoveTopRight", callback=callback)

    def ptz_move_bottom_left(self, callback=None):
        """
        Move to bottom left.
        """
        return self.execute_command("ptzMoveBottomLeft", callback=callback)

    def ptz_move_bottom_right(self, callback=None):
        """
        Move to bottom right.
        """
        return self.execute_command("ptzMoveBottomRight", callback=callback)

    def ptz_stop_run(self, callback=None):
        """
        Stop run PT
        """
        return self.execute_command("ptzStopRun", callback=callback)

    def ptz_reset(self, callback=None):
        """
        Reset PT to default position.
        """
        return self.execute_command("ptzReset", callback=callback)

    def ptz_get_preset(self, callback=None):
        """
        Get presets.
        """
        return self.execute_command("getPTZPresetPointList", callback=callback)

    def ptz_goto_preset(self, name, callback=None):
        """
        Move to preset.
        """
        params = {"name": name}
        return self.execute_command("ptzGotoPresetPoint", params, callback=callback)

    def get_ptz_speed(self, callback=None):
        """
        Get the speed of PT
        """
        return self.execute_command("getPTZSpeed", callback=callback)

    def set_ptz_speed(self, speed, callback=None):
        """
        Set the speed of PT
        """
        return self.execute_command("setPTZSpeed", {"speed": speed}, callback=callback)

    def get_ptz_selftestmode(self, callback=None):
        """
        Get the selftest mode of PTZ
        """
        return self.execute_command("getPTZSelfTestMode", callback=callback)

    def set_ptz_selftestmode(self, mode=0, callback=None):
        """
        Set the selftest mode of PTZ
        mode = 0: No selftest
        mode = 1: Normal selftest
        mode = 1: After normal selftest, then goto presetpoint-appointed
        """
        return self.execute_command(
            "setPTZSelfTestMode", {"mode": mode}, callback=callback
        )

    def get_ptz_preset_point_list(self, callback=None):
        """
        Get the preset list.
        """
        return self.execute_command("getPTZPresetPointList", {}, callback=callback)

    def ptz_zoom_in(self, callback=None):
        """
        Get the preset list.
        Zoom In.
        """
        return self.execute_command("zoomIn", callback=callback)

    def ptz_zoom_out(self, callback=None):
        """
        Move to bottom right.
        """
        return self.execute_command("zoomOut", callback=callback)

    def ptz_zoom_stop(self, callback=None):
        """
        Stop run PT
        """
        return self.execute_command("zoomStop", callback=callback)

    def sleep(self, callback=None):
        """
        Rotate to sleep position and sleep
        """
        return self.execute_command("alexaSleep", callback=callback)

    def wake_up(self, callback=None):
        """
        Wakup camera
        """
        return self.execute_command("alexaWakeUp", callback=callback)

    def is_asleep(self, callback=None):
        """
        Wakup camera
        """
        ret, data = self.execute_command("getAlexaState", callback=callback)

        is_asleep = int(data["state"]) == 1 if ret == 0 else False

        return ret, is_asleep

    # *************** AV Function *******************
    def get_motion_detect_config(self, callback=None):
        """
        Get motion detect config
        """
        return self.execute_command("getMotionDetectConfig", callback=callback)

    def set_motion_detect_config(self, params, callback=None):
        """
        Get motion detect config
        """
        return self.execute_command("setMotionDetectConfig", params, callback=callback)

    def set_motion_detection(self, enabled=1):
        """
        Get the current config and set the motion detection on or off
        """
        result, current_config = self.get_motion_detect_config()
        if result != FOSCAM_SUCCESS:
            return result
        current_config["isEnable"] = enabled
        self.set_motion_detect_config(current_config)
        return FOSCAM_SUCCESS

    def enable_motion_detection(self):
        """
        Enable motion detection
        """
        result = self.set_motion_detection(1)
        return result

    def disable_motion_detection(self):
        """
        disable motion detection
        """
        result = self.set_motion_detection(0)
        return result

    # These API calls support FI9900P devices, which use a different CGI command
    def get_motion_detect_config1(self, callback=None):
        """
        Get motion detect config
        """
        return self.execute_command("getMotionDetectConfig1", callback=callback)

    def set_motion_detect_config1(self, params, callback=None):
        """
        Get motion detect config
        """
        return self.execute_command("setMotionDetectConfig1", params, callback=callback)

    def set_motion_detection1(self, enabled=1):
        """
        Get the current config and set the motion detection on or off
        """
        result, current_config = self.get_motion_detect_config1()
        if result != FOSCAM_SUCCESS:
            return result
        current_config["isEnable"] = enabled
        self.set_motion_detect_config1(current_config)

    def enable_motion_detection1(self):
        """
        Enable motion detection
        """
        self.set_motion_detection1(1)

    def disable_motion_detection1(self):
        """
        disable motion detection
        """
        self.set_motion_detection1(0)

    def get_alarm_record_config(self, callback=None):
        """
        Get alarm record config
        """
        return self.execute_command("getAlarmRecordConfig", callback=callback)

    def set_alarm_record_config(
        self,
        is_enable_prerecord=1,
        prerecord_secs=5,
        alarm_record_secs=300,
        callback=None,
    ):
        """
        Set alarm record config
        Return: set result(0-success, -1-error)
        """
        params = {
            "isEnablePreRecord": is_enable_prerecord,
            "preRecordSecs": prerecord_secs,
            "alarmRecordSecs": alarm_record_secs,
        }
        return self.execute_command("setAlarmRecordConfig", params, callback=callback)

    def get_local_alarm_record_config(self, callback=None):
        """
        Get local alarm-record config
        """
        return self.execute_command("getLocalAlarmRecordConfig", callback=callback)

    def set_local_alarm_record_config(
        self, is_enable_local_alarm_record=1, local_alarm_record_secs=30, callback=None
    ):
        """
        Set local alarm-record config
        `is_enable_local_alarm_record`: 0 disable, 1 enable
        """
        params = {
            "isEnableLocalAlarmRecord": is_enable_local_alarm_record,
            "localAlarmRecordSecs": local_alarm_record_secs,
        }
        return self.execute_command(
            "setLocalAlarmRecordConfig", params, callback=callback
        )

    def get_h264_frm_ref_mode(self, callback=None):
        """
        Get grame shipping reference mode of H264 encode stream.
        Return args:
                mode: 0 Normal reference mode
                      1 Two frames are seprated by four skipping frames
        """
        return self.execute_command("getH264FrmRefMode", callback=callback)

    def set_h264_frm_ref_mode(self, mode=1, callback=None):
        """
        Set frame shipping reference mode of H264 encode stream.
        params:
            `mode`: see docstr of meth::get_h264_frm_ref_mode
        """
        params = {"mode": mode}
        return self.execute_command("setH264FrmRefMode", params, callback)

    def get_schedule_record_config(self, callback=None):
        """
        Get schedule record config.
        cmd: getScheduleRecordConfig
        Return args:
                isEnable: 0/1
                recordLevel: 0 ~ ?
                spaceFullMode: 0 ~ ?
                isEnableAudio: 0/1
                schedule[N]: N <- (0 ~ 6)
        """
        return self.execute_command("getScheduleRecordConfig", callback=callback)

    def set_schedule_record_config(
        self,
        is_enable,
        record_level,
        space_full_mode,
        is_enable_audio,
        schedule0=0,
        schedule1=0,
        schedule2=0,
        schedule3=0,
        schedule4=0,
        schedule5=0,
        schedule6=0,
        callback=None,
    ):
        """
        Set schedule record config.
        cmd: setScheduleRecordConfig
        args: See docstring of meth::get_schedule_record_config
        """

        params = {
            "isEnable": is_enable,
            "isEnableAudio": is_enable_audio,
            "recordLevel": record_level,
            "spaceFullMode": space_full_mode,
            "schedule0": schedule0,
            "schedule1": schedule1,
            "schedule2": schedule2,
            "schedule3": schedule3,
            "schedule4": schedule4,
            "schedule5": schedule5,
            "schedule6": schedule6,
        }
        return self.execute_command(
            "setScheduleRecordConfig", params, callback=callback
        )

    def get_record_path(self, callback=None):
        """
        Get Record path: sd/ftp
        cmd: getRecordPath
        return args:
            path: (0,SD), (2, FTP)
            free: free size(K)
            total: total size(K)
        """
        return self.execute_command("getRecordPath", callback=callback)

    def set_record_path(self, path, callback=None):
        """
        Set Record path: sd/ftp
        cmd: setRecordPath
        param:
             path: (0,SD), (2, FTP)
        """
        params = {"Path": path}
        return self.execute_command("setRecordPath", params, callback=callback)

    # *************** SnapPicture Function *******************

    def snap_picture_2(self, callback=None):
        """
        Manually request snapshot. Returns raw JPEG data.
        cmd: snapPicture2
        """
        return self.execute_command("snapPicture2", {}, callback=callback, raw=True)

    # ******************* SMTP Functions *********************

    def set_smtp_config(self, params, callback=None):
        """
        Set smtp settings using the array of parameters
        """
        return self.execute_command("setSMTPConfig", params, callback=callback)

    def get_smtp_config(self, callback=None):
        """
        Get smtp settings using the array of parameters
        """
        return self.execute_command("getSMTPConfig", callback=callback)

    # ********************** Misc ****************************

    def get_log(self, offset, count=10, callback=None):
        """
        Retrieve log records from camera.
        cmd: getLog
        param:
           offset: log offset for first record
           count: number of records to return
        """
        params = {"offset": offset, "count": count}
        return self.execute_command("getLog", params, callback=callback)

    def print_ipinfo(self, returncode, params):
        if returncode != FOSCAM_SUCCESS:
            print("Failed to get IPInfo!")
            return
        print(f"IP: {params['ip']}, Mask: {params['mask']}")
