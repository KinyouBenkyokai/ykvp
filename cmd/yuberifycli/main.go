package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/kinyoubenkyokai/yuberify/lib/entity"
	"github.com/kinyoubenkyokai/yuberify/lib/holder"
	"github.com/kinyoubenkyokai/yuberify/lib/verifier"
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
			&cli.IntFlag{
				Name:  "p",
				Value: 123456,
				Usage: "PIN code",
			},
		},
		Action: func(cCtx *cli.Context) error {
			vc := cCtx.String("c")
			if vc == "" {
				log.Println("no verifiable credential specified")
				return nil
			}
			pin := cCtx.Int("p")
			if pin == 0 {
				pin = 123456
			}
			credentials, err := entity.UnmarshalCredential([]byte(vc))
			if err != nil {
				panic(err)
			}
			nonce, err := verifier.MakeNonce()
			if err != nil {
				return err
			}
			presentation, err := holder.SignPresentation(
				credentials,
				nonce,
				pin,
			)

			nicePrint(presentation, "Presentation")

			log.Println(pin)
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func nicePrint(i interface{}, name string) {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")

	fmt.Printf("\n***** %s *****\n\n", name)
	e.Encode(i)
}
