# whazzup
Whazzup生成器。通常需要搭配其他插件。

## 使用(开发)
```python3
from pyfsd.plugins.whazzup import whazzupGenerator

whazzup = whazzupGenerator.generateWhazzup(heading_instead_pbh=False)
```
参数:  
heading\_instead\_pbh: 是否生成"heading"(航向)字段而非"pbh"字段(bool值)
```

### 关于pbh字段
可解析出俯仰角，侧滑角和航向角  
解析方法请看[X-Pilot源码](https://github.com/xpilot-project/xpilot/blob/b7a2375be88e8201c2c3fd8a353ace86f7ef49c3/client/src/fsd/pdu/pdu_base.cpp#L51-L82)
