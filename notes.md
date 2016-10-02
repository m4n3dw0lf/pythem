在`completer.py`里面，</br>

```python
# It should return the next possible completion starting with 'text'.
def pythem(self, text, state):

	#print text
	#print state
	# 只要按TAB键时，已经输入的字符串包含"set"，即便是"seta"也可以出现提示。
	if "set" in text and state == 1:
		self.suboptions = ['interface','arpmode','target','gateway','file','domain','port','script','redirect']
		completer = readline.set_completer(self.suboption)
```
这样写有点bug，就是只要按TAB键时，已经输入的字符串包含"set"，即便是"seta"也可以出现提示。</br>
而且，将前面的已经有的词清除之后留下空白，依然可以得到之前得到的提示。
![](img/屏幕快照 2016-08-01 下午3.35.07.png)

`pythem> service ssh start`
这里的`service`并不在`interface.py`里的`self.input_list[0]`判断之列，应该是用的操作系统命令。
这里是为了确保ssh服务开启了。由于之前在启动`pythem`的时候的判断已经确保了是root用户执行这个命令了，所以这里不需要加`sudo`了。

发现有个问题，就是提示输入
`[+] Enter the target(s):`时，没有做判断
直接就
```python
if self.targets is not None and self.interface is not None:
		from modules.scanner import Scanner
		self.scan = Scanner(self.targets, self.interface, mode)
```
看来这些开源软件漏洞也是蛮多的嘛，
![](img/屏幕快照 2016-08-01 下午5.28.49.png)
重新输入有效的ip之后成功了。

