 Microsoft has provided a way to block the ProxyNotShell attacks by using the URL rewrite rules on each exchange server.
Ref - https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/
 
 But there is also an alternative way to block the ProxyNotShell attack by levaraging the iRules in F5.
 Since exchange servers are typically load balanced and if you use F5, requests would go thorough the dedicated F5 VIP for exchange server, the same logic can be applied as iRule to block bad requests across all the exchange servers without making any changes on the servers.
 
 iRule in this repository when attached to the F5 load balancer VIP fronting exchange servers would drop any request matching the below regex ".*autodiscover\.json.*\@.*powershell.*"
 This is similar to the URL rewrite rule applied to each exchange server but applied only at one place - the VIP fronting the exchange servers.
 Advantage of applying using iRule is :
 1) The bad request would not even reach the exchange servers and rejected right at F5.
 2) Any enhancement to the regex can be applied here and that would protect all the exchange servers immediately 
 instead of potential change to the  url rewrite rule on each exchange servers.


![image](https://user-images.githubusercontent.com/1037523/193436834-3d8c4990-5e04-4421-957b-4787f479be31.png)

