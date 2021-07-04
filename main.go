package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
)

//读取key=value类型的配置文件
func InitConfig(path string) map[string]string {
	config := make(map[string]string)

	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	r := bufio.NewReader(f)
	for {
		b, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}
		s := strings.TrimSpace(string(b))
		if s[:2] == "//" {
			continue
		}
		index := strings.Index(s, "=")
		if index < 0 {
			continue
		}
		key := strings.TrimSpace(s[:index])
		if len(key) == 0 {
			continue
		}
		value := strings.TrimSpace(s[index+1:])
		if len(value) == 0 {
			continue
		}
		config[key] = value
	}
	return config
}

// const (
// 	// 襄阳流量墙 biandechao
// 	QIANGCOOKIE = "csrftoken=nF907rNaQUxV1Plh7Edxj9fkI3hTjVt2qG8Sso8vjF0PLOrLefA5jW08L7XvM0wV; Firewall=76qfkjtuqueq00nnggs79k74f97h1tcn; language=zh"
// 	// 襄阳流量墙地址
// 	QIANGURL = "http://111.177.16.18:16010"
// 	// 登录地址
// 	// LOGINURL = "/user_management/excutelogin"
// 	// 主页地址
// 	INDEXURL = "/user_management/ad_index/"
// 	// 域名过白地址
// 	ADDDOMAINWHITELISTURL = "/domainfilter/addDomainWhiteList/"
// 	// 备案ip文件
// 	DOMAINFILE = "beian.txt"
// 	// 过白失败ip文件
// 	DOMAINFALSEFILE = "falsebeian.txt"
// 	//备案地址
// 	BEIANURL = "http://upicp.aodun.com.cn:5000/query_domain_record_info" //?domain="
// )

// 检查cookie是否有效，无效直接退出
func checkLogin() {
	body, _ := httpGet(configmap["QIANGURL"]+configmap["INDEXURL"], "", true)
	// r := regexp.MustCompile("用户登录超时")
	// b := r.MatchString(body)
	// fmt.Println(b)
	r, _ := regexp.MatchString(`用户登录超时`, body)
	if r {
		fmt.Println(configmap["QIANGURL"], "cookie is err! exit!")
		os.Exit(1)
	}
	fmt.Println(configmap["QIANGURL"], "login is ok!")
}

// http GET 请求函数
func httpGet(url, cookie string, cookieflag bool) (string, error) {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	if cookieflag {
		if cookie == "" {
			cookie = configmap["QIANGCOOKIE"]
		}
		req.Header.Set("Cookie", cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	return string(body), err
}

// http POST 请求函数
func httpPost(url, cookie string, cookieflag bool, data string) (map[string]interface{}, error) {
	client := &http.Client{}
	req, _ := http.NewRequest("POST", url, strings.NewReader(data))
	if cookieflag {
		if cookie == "" {
			cookie = configmap["QIANGCOOKIE"]
		}
		req.Header.Set("Cookie", cookie)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	body, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		err = json.Unmarshal(body, &result)
	}
	defer resp.Body.Close()
	return result, err
}

// 获取文件内容
func getFileContent(filename string) string {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Get", filename, "Content is err!")
		os.Exit(3)
	}
	str := string(b)
	return str
}

// 域名处理
func domainHandle(domainname string, falsebeian *[]string) bool {
	// 计数器 -1
	defer wg.Done()
	// 查备案
	req, _ := http.NewRequest("GET", configmap["BEIANURL"], nil)
	q := req.URL.Query()
	// 添加GET请求数据
	q.Add("domain", domainname)
	req.URL.RawQuery = q.Encode()
	// fmt.Println(req.URL.String())
	var resp *http.Response
	// GET请求
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf(configmap["BEIANURL"] + "is err! exit!")
		os.Exit(4)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	// 输出备案信息
	fmt.Println("# " + domainname + " " + string(body))
	// 若无备案信息
	if string(body) == "false" {
		// 添加到falselist
		mutex.Lock()
		*falsebeian = append(*falsebeian, domainname)
		domainfalse++
		mutex.Unlock()
		return false
	}
	// 加白
	r, _ := httpPost(configmap["QIANGURL"]+configmap["ADDDOMAINWHITELISTURL"], "", true, "F_host=*."+domainname)
	fmt.Println("*."+domainname, r["msg"])
	// 加锁
	mutex.Lock()
	domainok++
	// 解锁
	mutex.Unlock()
	return true
}

// 检查文件是否存在
func checkFilesExist(filename string) bool {
	exist := true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

// 保存未备案域名至文件falsebeian.txt
func saveFile(falsebeian string) {
	filename := configmap["DOMAINFALSEFILE"]
	var f *os.File
	if checkFilesExist(filename) {
		f, _ = os.OpenFile(filename, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
	} else {
		f, _ = os.Create(filename)
	}
	io.WriteString(f, falsebeian)
}

// 锁
var mutex sync.Mutex
var wg sync.WaitGroup
var domainok int
var domainfalse int

// 配置文件
var configmap map[string]string = InitConfig("setting")

func main() {
	fmt.Println("The domain name is too white! run!")
	// 检查cookie
	checkLogin()
	// 获取需要加白的域名
	domaincontent := getFileContent(configmap["DOMAINFILE"])
	domainlist := strings.Fields(domaincontent)
	wg.Add(len(domainlist))
	// 循环加白
	var falsebeianlist []string
	for _, domainname := range domainlist {
		go domainHandle(domainname, &falsebeianlist)
	}
	wg.Wait()
	falsebeian := strings.Join(falsebeianlist, "\n")
	// 保存未备案信息至文件
	saveFile(falsebeian)
	fmt.Println("------------------------------------------------------")
	fmt.Println("Total white domain names:", domainok)
	fmt.Println("White domain name failed:", domainfalse)
	fmt.Printf("When the program is finished, enter to finish:")
	var str string
	fmt.Scanln(&str)
}
