# HTTPAPI
为数据库操作等设计的HTTP API。可扩展，文档稍后写

## 配置
```toml
[plugin.httpapi]
port = 端口(整数,例:8080)
client_coding = 生成whazzup的编码,完整列表请见https://docs.python.org/zh-cn/3/library/codecs.html#standard-encodings(文字,例:utf-8或gbk)
use_heading = whazzup中是否提供航向角而非pbh。详情请参阅whazzup插件文档(bool值,true或false)
token = 敏感API鉴权用的token(文字,例:j9AeC46KpbsljcTBXx_p_iacIP0TfFqRUUgGK4grT54(请勿沿用!))
```

## API
GET /whazzup.json Whazzup  
  
GET /users 获取全体信息  
返回格式(JSON): {"rating": {"等级": ["呼号1", "呼号2"]}}  
例: {"rating": {"1": ["1012", "6067"], "2": ["2728", "3117"]}}  
代表等级1的呼号有1012,6067,等级2的呼号有2728,3117  
  
GET /users/呼号 获取指定呼号的信息  
返回格式(JSON): {"exist": 布尔值, "rating": 整数(exist为真时才返回)}  
exist: 呼号是否存在。当呼号存在时会一并返回等级: rating(整数)  
  
PUT /users 注册呼号  
需要鉴权  
需要json格式body。body格式: {"callsign": 呼号, "password": sha256加密的密码}  
返回HTTP 503: 服务器还没准备好，一般不会出现，真出现了建议一两秒之后再试  
返回HTTP 409: 此呼号已存在  
返回HTTP 204: 创建成功  
  
PATCH /users/呼号 修改呼号信息  
需要鉴权  
需要json格式body。body格式: {"password": (可选)sha256加密的密码, "rating": (可选)等级}  
password或rating必须存在一个（不然你修改什么）  
返回HTTP 503: 服务器还没准备好，一般不会出现，真出现了建议一两秒之后再试  
返回HTTP 404: 呼号不存在  
返回HTTP 204: 修改成功  
  
POST /users 验证密码  
需要鉴权  
需要json格式body。body格式: {"callsign": 呼号, "password": sha256加密的密码}  
返回HTTP 503: 服务器还没准备好，一般不会出现，真出现了建议一两秒之后再试  
返回HTTP 200: 返回格式(JSON): {"exist": 布尔值, "rating": 整数(exist为真时才返回), "success": 布尔值(exist为真时才返回)}  
exist: 呼号是否存在。当呼号存在时会一并返回等级及密码是否正确: rating(整数), success(布尔值)  
  
DELETE /users/callsign 删除呼号  
需要鉴权  
返回HTTP 503: 服务器还没准备好，一般不会出现，真出现了建议一两秒之后再试  
返回HTTP 404: 呼号不存在  
返回HTTP 204: 删除成功  
  
鉴权方式：  
添加到header:  
Authorization: Bearer 上文配置的token  
  
注：所有接口都会返回json，但是一些接口通过http状态码就能判断结果，文档就省去了  
返回HTTP 400不正常，建议查看返回的json的title字段  
返回HTTP 500不正常，服务器错误，建议提个issue并附日志  
返回HTTP 501不正常，看一下是不是用错方法了，只支持GET, POST或者DELETE方法  
