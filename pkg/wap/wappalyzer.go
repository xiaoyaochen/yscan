package wap

import (
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"sync"

	jsoniter "github.com/json-iterator/go"
	log "github.com/sirupsen/logrus"
)

type temp struct {
	Apps       map[string]*jsoniter.RawMessage `json:"technologies"`
	Categories map[string]*jsoniter.RawMessage `json:"categories"`
}

type application struct {
	Slug       string
	Name       string             `json:"name,omitempty"`
	Version    string             `json:"version"`
	Categories []extendedCategory `json:"categories,omitempty"`
	Icon       string             `json:"icon,omitempty"`
	Website    string             `json:"website,omitempty"`
	CPE        string             `json:"cpe,omitempty"`

	Cats       []int       `json:"cats,omitempty"`
	Cookies    interface{} `json:"cookies,omitempty"`
	Dom        interface{} `json:"dom,omitempty"`
	Js         interface{} `json:"js,omitempty"`
	Headers    interface{} `json:"headers,omitempty"`
	HTML       interface{} `json:"html,omitempty"`
	Excludes   interface{} `json:"excludes,omitempty"`
	Implies    interface{} `json:"implies,omitempty"`
	Meta       interface{} `json:"meta,omitempty"`
	Scripts    interface{} `json:"scripts,omitempty"`
	DNS        interface{} `json:"dns,omitempty"`
	URL        interface{} `json:"url,omitempty"`
	CertIssuer string      `json:"certIssuer,omitempty"`
}

type category struct {
	Name     string `json:"name,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

type extendedCategory struct {
	ID       int    `json:"id"`
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	Priority int    `json:"-"`
}

// Wappalyzer implements analyze method as original wappalyzer does
type Wappalyzer struct {
	Apps       map[string]*application
	Categories map[string]*extendedCategory
}

func parseTechnologiesFile(appsFile *[]byte, wapp *Wappalyzer) error {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	temporary := &temp{}
	err := json.Unmarshal(*appsFile, &temporary)
	if err != nil {
		log.Errorf("Couldn't unmarshal apps.json file: %s\n", err)
		return err
	}
	wapp.Apps = make(map[string]*application)
	wapp.Categories = make(map[string]*extendedCategory)
	for k, v := range temporary.Categories {
		catg := &category{}
		if err = json.Unmarshal(*v, catg); err != nil {
			log.Errorf("[!] Couldn't unmarshal Categories: %s\n", err)
			return err
		}
		catID, err := strconv.Atoi(k)
		if err == nil {
			slug, err := slugify(catg.Name)
			if err == nil {
				extCatg := &extendedCategory{catID, slug, catg.Name, catg.Priority}
				wapp.Categories[k] = extCatg
			}
		}
	}
	if len(wapp.Categories) < 1 {
		log.Errorf("Couldn't find categories in technologies file")
		return errors.New("NoCategoryFound")
	}
	for k, v := range temporary.Apps {
		app := &application{}
		app.Name = k
		if err = json.Unmarshal(*v, app); err != nil {
			log.Errorf("Couldn't unmarshal Apps: %s\n", err)
			return err
		}
		parseCategories(app, &wapp.Categories)
		app.Slug, err = slugify(app.Name)
		wapp.Apps[k] = app
	}
	if len(wapp.Apps) < 1 {
		log.Errorf("Couldn't find technologies in technologies file")
		return errors.New("NoTechnologyFound")
	}
	return err
}

// addApp add a detected app to the detectedApplications
// if the app is already detected, we merge it (version, confidence, ...)
func addApp(app *application, detectedApplications *detected, version string, confidence int) {
	detectedApplications.Mu.Lock()
	if _, ok := (*detectedApplications).Apps[app.Name]; !ok {
		resApp := &resultApp{technology{app.Slug, app.Name, confidence, version, app.Icon, app.Website, app.CPE, app.Categories}, app.Excludes, app.Implies}
		(*detectedApplications).Apps[resApp.technology.Name] = resApp
	} else {
		if (*detectedApplications).Apps[app.Name].technology.Version == "" {
			(*detectedApplications).Apps[app.Name].technology.Version = version
		}
		if confidence > (*detectedApplications).Apps[app.Name].technology.Confidence {
			(*detectedApplications).Apps[app.Name].technology.Confidence = confidence
		}
	}
	detectedApplications.Mu.Unlock()
}

// detectVersion tries to extract version from value when app detected
func detectVersion(pattrn *pattern, value *string) (res string) {
	if pattrn.regex == nil {
		return ""
	}
	versions := make(map[string]interface{})
	version := pattrn.version
	if slices := pattrn.regex.FindAllStringSubmatch(*value, -1); slices != nil {
		for _, slice := range slices {
			for i, match := range slice {
				reg, _ := regexp.Compile(fmt.Sprintf("%s%d%s", "\\\\", i, "\\?([^:]+):(.*)$"))
				ternary := reg.FindStringSubmatch(version)
				if len(ternary) == 3 {
					if match != "" {
						version = strings.Replace(version, ternary[0], ternary[1], -1)
					} else {
						version = strings.Replace(version, ternary[0], ternary[2], -1)
					}
				}
				reg2, _ := regexp.Compile(fmt.Sprintf("%s%d", "\\\\", i))
				version = reg2.ReplaceAllString(version, match)
			}
		}
		if _, ok := versions[version]; !ok && version != "" {
			versions[version] = struct{}{}
		}
		if len(versions) != 0 {
			for ver := range versions {
				if ver > res {
					res = ver
				}
			}
		}
	}
	return res
}

// slugify returns the slug string from an input string
func slugify(str string) (ret string, err error) {
	ret = strings.ToLower(str)
	reg, err := regexp.Compile(`[^a-z0-9-]`)
	if err == nil {
		ret = reg.ReplaceAllString(ret, "-")
		reg, err = regexp.Compile(`--+`)
		if err == nil {
			ret = reg.ReplaceAllString(ret, "-")
			reg, err = regexp.Compile(`(?:^-|-$)`)
			ret = reg.ReplaceAllString(ret, "")
		}
	}
	return ret, err
}

func parseCategories(app *application, categoriesCatalog *map[string]*extendedCategory) {
	for _, categoryID := range app.Cats {
		app.Categories = append(app.Categories, *(*categoriesCatalog)[strconv.Itoa(categoryID)])
	}
}

func InitApp(appsjsonpath string) (wapp *Wappalyzer, err error) {
	var appsFile []byte
	if appsjsonpath != "" {
		log.Infof("Trying to open technologies file at %s", appsjsonpath)
		appsFile, err = ioutil.ReadFile(appsjsonpath)
		if err != nil {
			log.Warningf("Couldn't open file at %s\n", appsjsonpath)
		} else {
			log.Infof("Technologies file opened")
		}
	}
	if appsjsonpath == "" || len(appsFile) == 0 {
		log.Infof("Loading technologies default %s", appsjsonpath)
		appsFile = []byte(technologies)
		// appsFile, err = ioutil.ReadFile("technologies.json")
		// if err != nil {
		// 	log.Errorf("Couldn't open included asset %s\n", "technologies.json")
		// 	return nil, err
		// }
	}
	wapp = &Wappalyzer{}
	err = parseTechnologiesFile(&appsFile, wapp)
	return wapp, err
}

type technology struct {
	Slug       string             `json:"slug"`
	Name       string             `json:"name"`
	Confidence int                `json:"confidence"`
	Version    string             `json:"version"`
	Icon       string             `json:"-"`
	Website    string             `json:"-"`
	CPE        string             `json:"-"`
	Categories []extendedCategory `json:"categories"`
}

type resultApp struct {
	technology technology
	excludes   interface{}
	implies    interface{}
}

type detected struct {
	Mu   *sync.Mutex
	Apps map[string]*resultApp
}

type pattern struct {
	str        string
	regex      *regexp.Regexp
	version    string
	confidence int
}

func parsePatterns(patterns interface{}) (result map[string][]*pattern) {
	parsed := make(map[string][]string)
	switch ptrn := patterns.(type) {
	case string:
		parsed["main"] = append(parsed["main"], ptrn)
	case map[string]interface{}:
		for k, v := range ptrn {
			switch content := v.(type) {
			case string:
				parsed[k] = append(parsed[k], v.(string))
			case []interface{}:
				for _, v1 := range content {
					parsed[k] = append(parsed[k], v1.(string))
				}
			default:
				log.Errorf("Unknown type in parsePatterns: %T\n", v)
			}
		}
	case []interface{}:
		var slice []string
		for _, v := range ptrn {
			slice = append(slice, v.(string))
		}
		parsed["main"] = slice
	default:
		log.Errorf("Unknown type in parsePatterns: %T\n", ptrn)
	}
	result = make(map[string][]*pattern)
	for k, v := range parsed {
		for _, str := range v {
			appPattern := &pattern{confidence: 100}
			slice := strings.Split(str, "\\;")
			for i, item := range slice {
				if item == "" {
					continue
				}
				if i > 0 {
					additional := strings.SplitN(item, ":", 2)
					if len(additional) > 1 {
						if additional[0] == "version" {
							appPattern.version = additional[1]
						} else if additional[0] == "confidence" {
							appPattern.confidence, _ = strconv.Atoi(additional[1])
						}
					}
				} else {
					appPattern.str = item
					first := strings.Replace(item, `\/`, `/`, -1)
					second := strings.Replace(first, `\\`, `\`, -1)
					reg, err := regexp.Compile(fmt.Sprintf("%s%s", "(?i)", strings.Replace(second, `/`, `\/`, -1)))
					if err == nil {
						appPattern.regex = reg
					}
				}
			}
			result[k] = append(result[k], appPattern)
		}
	}
	return result
}

func AnalyzePage(crawlerdata *CrawlerData, wapp *Wappalyzer) (err error) {
	// var wg sync.WaitGroup
	// pool := make(chan int, 30)
	detectedApplications := &detected{new(sync.Mutex), make(map[string]*resultApp)}
	for _, app := range wapp.Apps {
		if app.URL != nil {
			analyzeURL(app, crawlerdata.ResURL, detectedApplications)
		}
		htmlLen := len(crawlerdata.HTML)
		if htmlLen > 0 && app.HTML != nil {
			if htmlLen < 6000 {
				analyzeHTML(app, crawlerdata.HTML, detectedApplications)
			} else {
				analyzeHTML(app, crawlerdata.HTML[:3000]+crawlerdata.HTML[htmlLen-3000:], detectedApplications)
			}
		}
		if len(crawlerdata.Headers) > 0 && app.Headers != nil {
			analyzeHeaders(app, crawlerdata.Headers, detectedApplications)
		}
		if len(crawlerdata.Cookies) > 0 && app.Cookies != nil {
			analyzeCookies(app, crawlerdata.Cookies, detectedApplications)
		}
		if len(crawlerdata.Scripts) > 0 && app.Scripts != nil {
			analyzeScripts(app, crawlerdata.Scripts, detectedApplications)
		}
		if len(crawlerdata.Meta) > 0 && app.Meta != nil {
			analyzeMeta(app, crawlerdata.Meta, detectedApplications)
		}
		// 	wg.Add(1)
		// 	pool <- 1
		// 	go func(app *application) {
		// 		defer wg.Done()
		// 		defer func() {
		// 			<-pool
		// 		}()
		// 		if app.URL != nil {
		// 			analyzeURL(app, crawlerdata.ResURL, detectedApplications)
		// 		}
		// 		if app.HTML != nil {
		// 			analyzeHTML(app, crawlerdata.HTML, detectedApplications)
		// 		}
		// 		if len(crawlerdata.Headers) > 0 && app.Headers != nil {
		// 			analyzeHeaders(app, crawlerdata.Headers, detectedApplications)
		// 		}
		// 		if len(crawlerdata.Cookies) > 0 && app.Cookies != nil {
		// 			analyzeCookies(app, crawlerdata.Cookies, detectedApplications)
		// 		}
		// 		if len(crawlerdata.Scripts) > 0 && app.Scripts != nil {
		// 			analyzeScripts(app, crawlerdata.Scripts, detectedApplications)
		// 		}
		// 		if len(crawlerdata.Meta) > 0 && app.Meta != nil {
		// 			analyzeMeta(app, crawlerdata.Meta, detectedApplications)
		// 		}
		// 	}(app)
	}

	// wg.Wait()

	for _, app := range detectedApplications.Apps {
		if app.excludes != nil {
			resolveExcludes(&detectedApplications.Apps, app.excludes)
		}
		if app.implies != nil {
			resolveImplies(&wapp.Apps, &detectedApplications.Apps, app.implies)
		}
	}
	for _, app := range detectedApplications.Apps {
		crawlerdata.Apps = append(crawlerdata.Apps, app.technology)
	}
	return nil
}

func analyzeURL(app *application, paramURL string, detectedApplications *detected) {
	patterns := parsePatterns(app.URL)
	for _, v := range patterns {
		for _, pattrn := range v {
			if pattrn.regex != nil && pattrn.regex.MatchString(paramURL) {
				version := detectVersion(pattrn, &paramURL)
				addApp(app, detectedApplications, version, pattrn.confidence)
			}
		}
	}
}

func analyzeHeaders(app *application, headers map[string][]string, detectedApplications *detected) {
	patterns := parsePatterns(app.Headers)
	for headerName, v := range patterns {
		headerNameLowerCase := strings.ToLower(headerName)
		for _, pattrn := range v {
			if headersSlice, ok := headers[headerNameLowerCase]; ok {
				for _, header := range headersSlice {
					if pattrn.str == "" || (pattrn.regex != nil && pattrn.regex.MatchString(header)) {
						version := detectVersion(pattrn, &header)
						addApp(app, detectedApplications, version, pattrn.confidence)
					}
				}
			}
		}
	}
}

func analyzeCookies(app *application, cookies map[string]string, detectedApplications *detected) {
	patterns := parsePatterns(app.Cookies)
	for cookieName, v := range patterns {
		cookieNameLowerCase := strings.ToLower(cookieName)
		for _, pattrn := range v {
			if cookie, ok := cookies[cookieNameLowerCase]; ok {
				if pattrn.str == "" || (pattrn.regex != nil && pattrn.regex.MatchString(cookie)) {
					version := detectVersion(pattrn, &cookie)
					addApp(app, detectedApplications, version, pattrn.confidence)
				}
			}
		}
	}
}

func analyzeHTML(app *application, html string, detectedApplications *detected) {
	patterns := parsePatterns(app.HTML)
	for _, v := range patterns {
		for _, pattrn := range v {
			if pattrn.regex != nil && pattrn.regex.MatchString(html) {
				version := detectVersion(pattrn, &html)
				addApp(app, detectedApplications, version, pattrn.confidence)
			}
		}

	}
}

func analyzeMeta(app *application, metas map[string][]string, detectedApplications *detected) {
	patterns := parsePatterns(app.Meta)
	for metaName, v := range patterns {
		metaNameLowerCase := strings.ToLower(metaName)
		for _, pattrn := range v {
			if metaSlice, ok := metas[metaNameLowerCase]; ok {
				for _, meta := range metaSlice {
					if pattrn.str == "" || (pattrn.regex != nil && pattrn.regex.MatchString(meta)) {
						version := detectVersion(pattrn, &meta)
						addApp(app, detectedApplications, version, pattrn.confidence)
					}
				}
			}
		}
	}
}

func analyzeScripts(app *application, scripts []string, detectedApplications *detected) {
	patterns := parsePatterns(app.Scripts)
	for _, v := range patterns {
		for _, pattrn := range v {
			if pattrn.regex != nil {
				for _, script := range scripts {
					if pattrn.regex.MatchString(script) {
						version := detectVersion(pattrn, &script)
						addApp(app, detectedApplications, version, pattrn.confidence)
					}
				}
			}
		}
	}
}

func resolveExcludes(detected *map[string]*resultApp, value interface{}) {
	patterns := parsePatterns(value)
	for _, v := range patterns {
		for _, excluded := range v {
			delete(*detected, excluded.str)
		}
	}
}

func resolveImplies(apps *map[string]*application, detected *map[string]*resultApp, value interface{}) {
	patterns := parsePatterns(value)
	for _, v := range patterns {
		for _, implied := range v {
			app, ok := (*apps)[implied.str]
			if _, ok2 := (*detected)[implied.str]; ok && !ok2 {
				resApp := &resultApp{technology{app.Slug, app.Name, implied.confidence, implied.version, app.Icon, app.Website, app.CPE, app.Categories}, app.Excludes, app.Implies}
				(*detected)[implied.str] = resApp
				if app.Implies != nil {
					resolveImplies(apps, detected, app.Implies)
				}
			}
		}
	}
}
