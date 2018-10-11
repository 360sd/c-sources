1   public CurrentUser currentUser
 2         {
 3             get
 4             {
 5                 CurrentUser result = new CurrentUser();
 6                 //jwt 解密token
 7                 IJsonSerializer serializer = new JsonNetSerializer();
 8                 IDateTimeProvider provider = new UtcDateTimeProvider();
 9                 IJwtValidator validator = new JwtValidator(serializer, provider);
10                 IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
11                 IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder);
12                 string authHeader = this.Request.Headers["Authorization"];//Header中的token
13                 // Add JWT　Protection
14                 if (authHeader != null && authHeader.StartsWith("Bearer"))
15                 {
16                     string token = authHeader.Substring("Bearer ".Length).Trim();
17                     var requestService = HttpContext.RequestServices;
18                     var conf = requestService.GetService(typeof(IConfiguration)) as IConfiguration;
19                     var secretKey = conf["AAA:BBB"];//密钥信息
20                     string resultstr = decoder.Decode(token, secretKey, verify: true);//token为之前生成的字符串
21 
22                     result = JsonConvert.DeserializeObject<CurrentUser>(resultstr);//反序列化 将jwt中的信息解压出来
23                 }
24                 else
25                 {
26                     //Handle what happens if that isn't the case
27                     throw new Exception("The authorization header is either empty or isn't Basic.");
28                 }
29                 return result;
30             }
31         }
