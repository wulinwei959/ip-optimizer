// hosts-optimizer：定时为自定义域名优选可用 IP，生成 hosts / AdGuard Home 订阅。
// 仅使用 Go 标准库，可 CGO_ENABLED=0 交叉编译为单个静态二进制。
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata" // 静态二进制自带时区库，HO_TZ 不依赖宿主的 /usr/share/zoneinfo

	"hosts-optimizer/internal/app"
	"hosts-optimizer/internal/config"
)

const version = "1.0.1"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[hosts-optimizer] ")

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-version", "version":
			fmt.Println("hosts-optimizer", version)
			return
		case "-check-config":
			rt, err := config.Load()
			if err != nil {
				log.Fatalf("配置错误: %v", err)
			}
			fmt.Printf("配置有效：%d 个域名，探测周期 %d 分钟，端口 %s，上游 DNS %v\n",
				len(rt.Config.Domains), rt.Config.Defaults.ScheduleMinutes, rt.Port, rt.Config.Defaults.ProbeDNS)
			return
		default:
			log.Fatalf("未知参数 %q（可用：-version、-check-config）", os.Args[1])
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rt, err := config.Load()
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	if loc, err := time.LoadLocation(rt.TZ); err == nil {
		time.Local = loc
	} else {
		log.Printf("时区 %q 不可用，使用系统本地时区: %v", rt.TZ, err)
	}

	a, err := app.New(rt)
	if err != nil {
		log.Fatalf("初始化失败: %v", err)
	}
	log.Printf("hosts-optimizer %s 启动：配置=%s 产物=%s 状态=%s 端口=%s",
		version, rt.ConfigDir, rt.OutputDir, rt.StateDir, rt.Port)
	if err := a.Run(ctx); err != nil {
		log.Fatalf("运行结束: %v", err)
	}
	log.Printf("已停止")
}
