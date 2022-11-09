resource "xray_licenses_report" "report" {

  name 							= "test-license-report"
  resources {
    repository {
      name 					    = "reponame"
      include_path_patterns 	= ["pattern1","pattern2"]
      exclude_path_patterns 	= ["pattern2","pattern2"]
    }
    repository {
      name 					    = "reponame1"
      include_path_patterns 	= ["pattern1","pattern2"]
      exclude_path_patterns 	= ["pattern1","pattern2"]
    }
  }
  filters {
    component 			= "component-name"
    artifact 			= "impacted-artifact"
    unknown 			= false
    unrecognized 		= true
    license_names 		= ["Apache","MIT"]
    scan_date {
      start 			= "2020-06-29T12:22:16Z"
      end				= "2020-07-29T12:22:16Z"
    }
  }
}