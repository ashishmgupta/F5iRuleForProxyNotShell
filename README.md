 Microsoft has provided a way to block the ProxyNotShell attacks by using the URL rewrite rules on each exchange server.
 ref - https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/
 
 But there is also an alternative way to block the ProxyNotShell attack by levaraging the iRules in F5.
 Since exchange servers are typically load balanced and requests go thorough the dedicated F5 VIP for exchange server, the same logic can be applied to block bad requests.
 
 iRule in this repository when attached to the F5 load balancer VIP fronting exchange servers would drop any request matching the below regex ".*autodiscover\.json.*\@.*powershell.*"
 This is similar to the URL rewrite rule applied to each exchange server but applied only at one place - the VIP fronting the exchange servers.
 Advantage of applying using iRule is :
 1) The bad request would not even reach the exchange servers and rejected right at F5.
 2) Any enhancement to the regex can be applied here and that would protect all the exchange servers immediately 
 instead of potential change to the  url rewrite rule on each exchange servers.


![image](https://user-images.githubusercontent.com/1037523/193436390-05ba7eff-5154-463a-9f43-f7c6ddb653fc.png)
