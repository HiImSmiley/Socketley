#pragma once
// What is inside a message from elsewhere that it is refused for: an attachment of a kind that runs (a program, a
// script, a document with macros), or what ClamAV's clamd finds when the message is streamed to it (INSTREAM).
#include <string>
#include <string_view>

namespace socketley::mail
{

// The extensions refused unless --refuse-attachments says others: programs, scripts, shortcuts, disk images and
// Office documents that carry macros, as Gmail refuses them.
inline constexpr std::string_view default_refused_attachments =
    "ade,adp,app,bat,cab,chm,cmd,com,cpl,dll,docm,dotm,exe,hta,iso,img,jar,js,jse,lnk,msc,msi,msp,pif,potm,ppam,ppsm,"
    "pptm,ps1,psm1,reg,scr,sct,shb,sys,vb,vbe,vbs,vhd,vhdx,wsc,wsf,wsh,xlam,xlsm,xltm";

// The name of the first attachment of `msg` whose extension `list` names ("default", or "none" for none), empty for none.
std::string refused_attachment(std::string_view msg, std::string_view list);

struct virus_verdict
{
    bool scanned{false};
    // What clamd named, empty for nothing found.
    std::string found;
    std::string why;
};

// `msg` streamed to the clamd at `where`, host:port or a unix socket's path; unscanned, with why, where it does not
// answer within `timeout_s`, which leaves the message taken.
virus_verdict clamav_scan(const std::string& where, std::string_view msg, int timeout_s = 20);

}   // namespace socketley::mail
