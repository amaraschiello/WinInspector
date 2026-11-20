<?xml version="1.0" encoding="UTF-8"?>
<!--
  WinInspector IIS Configuration — Option 2: IIS Reverse Proxy (ARR + URL Rewrite)
  Prerequisites on IIS Server:
    1. Install IIS Application Request Routing (ARR 3.0) + URL Rewrite 2.1
    2. Enable Proxy in ARR Server Proxy Settings (set Time-out to 300 seconds)
    3. Run server\Start-WinInspector.ps1 as a Windows Service (e.g., via WinSW/NSSM) on 127.0.0.1:8085
    4. Enable IIS Windows Authentication (Negotiate); Disable Anonymous Authentication
    5. Allow server variables HTTP_X_FORWARDED_USER and HTTP_X_FORWARDED_PROTO in URL Rewrite
    6. Copy this file to the IIS site root as web.config
-->
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="EnforceHTTPS" stopProcessing="true">
          <match url="(.*)" />
          <conditions>
            <add input="{HTTPS}" pattern="^OFF$" />
          </conditions>
          <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
        </rule>
        <rule name="ReverseProxyToPode" stopProcessing="true">
          <match url="(.*)" />
          <serverVariables>
            <set name="HTTP_X_FORWARDED_USER" value="{LOGON_USER}" />
            <set name="HTTP_X_FORWARDED_PROTO" value="https" />
          </serverVariables>
          <action type="Rewrite" url="http://127.0.0.1:8085/{R:1}" />
        </rule>
      </rules>
    </rewrite>

    <security>
      <authentication>
        <anonymousAuthentication enabled="false" />
        <windowsAuthentication enabled="true" />
      </authentication>
    </security>
  </system.webServer>
</configuration>
