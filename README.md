# DSA
<h3>基于GMP和Openssl实现DSA对任意文件签名验证</h3>

DSA具体过程:
![](https://github.com/GalaxyScrew/DSA/blob/master/DSA.jpg)

需要特别说明的是全局参数p,q的生成方法，不要只想着先求素数p再求p-1的素因子，官方的方法是先生成素数q，再用素数q去反过来求p.

stackoverflow的解决方案：https://stackoverflow.com/questions/8350568/dsa-how-to-generate-the-subprime
