/*
Copyright © 2021 ContainerCraft <emcee@braincraft.io>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	cowsay "github.com/usrbinkat/Neo-cowsay"
)

// sayCmd represents the say command
var sayCmd = &cobra.Command{
	Use:   "say",
	Short: "You've seen cowsay, get ready for keanu say",
	Long:  `WOAH!`,
	Run: func(cmd *cobra.Command, args []string) {
		say, err := cowsay.Say(
			cowsay.Phrase("I know kung foo"),
			cowsay.Type("keanu"),
			cowsay.BallonWidth(40),
		)
		if err != nil {
			panic(err)
		}
		fmt.Println(say)
	},
}

func init() {
	rootCmd.AddCommand(sayCmd)
}
