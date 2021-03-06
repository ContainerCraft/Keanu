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
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "keanu init [OPTIONS]",
	Short: "Keanu setup tasks",
	Long: `This function provides support for loading image
dependencies and other pre-flight checks such as host port
availability checking and pod creation.

Example:
  keanu init --preflight --cloudctl --registry`,
	Run: func(cmd *cobra.Command, args []string) {
		core()
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
	//	initCmd.Flag().BoolP("help", "h", false, "keanu init help")
	//	initCmd.Flags().Bool("&preflight", "F", true, "pre-flight host validation")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// initCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// initCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func core() {
	fmt.Println("init called")
}
