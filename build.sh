#!/usr/bin/env bash

projects=("nz2-spec")

for project in "${projects[@]}"; do
	if ! sed -r 's/#let darkmode = \w+/#let darkmode = false/' "${project}.typ" |
		typst compile - "${project}.light.pdf"; then

		echo "Failed to compile light mode PDF for ${project}."
		exit 1
	else
		echo "Successfully compiled light mode PDF for ${project}."
	fi

	if ! sed -r 's/#let darkmode = \w+/#let darkmode = true/' "${project}.typ" |
		typst compile - "${project}.dark.pdf"; then

		echo "Failed to compile dark mode PDF for ${project}."
		exit 1
	else
		echo "Successfully compiled dark mode PDF for ${project}."
	fi
done
