# Ashish Gupta
# ref - https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/
# Below iRule when attached to the F5 load balancer VIP fronting exchange servers would drop any request matching the below regex ".*autodiscover\.json.*\@.*powershell.*"
# This is similar to the URL rewrite rule applied to each exchange server but applied only at one place - the VIP fronting the exchange servers.
# Advantage of applying using iRule is :
# 1) The bad request would not even reach the exchange servers and rejected right at F5.
# 2) Any enhancement to the regex can be applied here and that would protect all the exchange servers immediately 
# instead of potential change to the  url rewrite rule on each exchange servers.


# ALTHOUGH ITS VERY SIMPLE BUT NO WARRANTIES. PLEASE TEST WELL AND PLEASE USE AT YOUR OWN RISK.
when RULE_INIT {
    # set it to 1 if debugging
    set static::proxynotshell_debug 1 
}

when HTTP_REQUEST { 
    if {[string tolower [HTTP::uri]] matches_regex {.*autodiscover\.json.*Powershell.*} } 
    {
       # Uncomment the below log local0 line during testing to see the matching logs in your LTM 
       if { $static::proxynotshell_debug } 
       { 
           log local0. "Matched and this request would be blocked! :  [HTTP::uri]" 
       }
       drop
    }
    else
    {
       if { $static::proxynotshell_debug } 
       { 
           log local0. "Not matched and and this request would be sent to a backened server! :  [HTTP::uri]" 
       }
    }
}
