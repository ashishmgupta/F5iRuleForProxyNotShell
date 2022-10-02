# Ashish Gupta
# Ref : https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/
# Below iRule when attached to the F5 load balancer VIP fronting exchange servers would drop any request matching the below regex ".*autodiscover\.json.*\@.*powershell.*"
# This is similar to the URL rewrite rule applied to each exchange server but applied only at one place - the VIP fronting the exchange servers.
# Advantages of using iRule is :
# 1) The bad request would not even reach the exchange servers and rejected right at F5.
# 2) Any enhancement to the regex can be applied here and that would protect all the exchange servers immediately 
# instead of potential change to the url rewrite rule on each exchange servers.

when HTTP_REQUEST { 
    if {[string tolower [HTTP::uri]] matches_regex {.*autodiscover\.json.*\@.*powershell.*} } 
    {
       # Uncomment the below log local0 line during testing to see the matching logs in your LTM 
       # log local0. "Matched :  [HTTP::uri]" 
       drop
    }
}
