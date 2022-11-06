package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "",
		Usage: "",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "c",
				Usage: "Verifiable Credential",
			},
			&cli.StringFlag{
				Name:  "p",
				Value: "123456",
				Usage: "PIN code",
			},
			&cli.StringFlag{
				Name:  "s",
				Usage: "Identifier for the only subject of the credential",
			},
		},
		Action: func(cCtx *cli.Context) error {
			vc := cCtx.String("c")
			if vc == "" {
				log.Println("no verifiable credential specified")
				return nil
			}
			pin := cCtx.String("p")
			if pin == "" {
				pin = "123456"
			}
			log.Println(vc)
			log.Println(pin)
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
