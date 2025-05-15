
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { AlertTriangle, FileWarning, Bug, ShieldAlert, Settings2 } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export function ThreatSources() {
  const [activeTab, setActiveTab] = useState("sources");
  
  const threatSources = [
    {
      name: "Malicious Emails",
      count: 15,
      severity: "High",
      description: "Phishing attempts and malware attachments",
      percentage: 35,
      trend: "increasing"
    },
    {
      name: "Network Intrusion",
      count: 8,
      severity: "Medium",
      description: "Unauthorized access attempts",
      percentage: 22,
      trend: "stable"
    },
    {
      name: "Ransomware Signatures",
      count: 3,
      severity: "Critical",
      description: "File encryption attempts",
      percentage: 16,
      trend: "decreasing"
    },
    {
      name: "Malicious URLs",
      count: 12,
      severity: "Medium",
      description: "Links to malicious websites",
      percentage: 18,
      trend: "increasing"
    },
    {
      name: "Insider Threats",
      count: 2,
      severity: "Low",
      description: "Suspicious internal activities",
      percentage: 9,
      trend: "stable"
    }
  ];
  
  const remediations = [
    {
      threat: "Malicious Emails",
      actions: [
        "Deploy email filtering solution",
        "Train staff to identify phishing attempts",
        "Implement DMARC, SPF and DKIM"
      ],
      priority: "High",
      difficulty: "Medium",
      automatable: true
    },
    {
      threat: "Network Intrusion",
      actions: [
        "Update firewall rules",
        "Implement network segmentation",
        "Deploy intrusion detection system"
      ],
      priority: "High",
      difficulty: "High",
      automatable: false
    },
    {
      threat: "Ransomware Signatures",
      actions: [
        "Update antivirus definitions",
        "Implement application whitelisting",
        "Create offline backups",
        "Disable macros in Office documents"
      ],
      priority: "Critical",
      difficulty: "Medium",
      automatable: true
    },
    {
      threat: "Malicious URLs",
      actions: [
        "Deploy web filtering solution",
        "Update browser security settings",
        "Implement DNS filtering"
      ],
      priority: "Medium",
      difficulty: "Low",
      automatable: true
    },
    {
      threat: "Insider Threats",
      actions: [
        "Review access permissions",
        "Implement least privilege principle",
        "Deploy behavior analysis tools"
      ],
      priority: "Medium",
      difficulty: "High",
      automatable: false
    }
  ];

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200';
      case 'low': return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200';
      default: return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200';
    }
  };
  
  const getPriorityColor = (priority) => {
    switch (priority.toLowerCase()) {
      case 'critical': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200';
      case 'low': return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200';
      default: return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200';
    }
  };
  
  const getTrendIcon = (trend) => {
    switch (trend) {
      case 'increasing':
        return <span className="text-red-500">↑</span>;
      case 'decreasing':
        return <span className="text-green-500">↓</span>;
      default:
        return <span className="text-gray-500">→</span>;
    }
  };

  return (
    <Card className="border border-gray-200 dark:border-gray-700 shadow-sm">
      <CardHeader className="pb-2">
        <CardTitle className="text-xl flex items-center">
          <ShieldAlert className="h-5 w-5 mr-2 text-red-500" />
          Threat Analysis & Remediation
        </CardTitle>
        <CardDescription>
          Identify threat sources and recommended actions
        </CardDescription>
        <Tabs defaultValue="sources" className="w-full" onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="sources">Threat Sources</TabsTrigger>
            <TabsTrigger value="remediation">Remediation Plans</TabsTrigger>
          </TabsList>
        </Tabs>
      </CardHeader>
      <CardContent>
        <TabsContent value="sources" className="mt-0">
          <div className="space-y-4">
            {threatSources.map((source, index) => (
              <div key={index} className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
                <div className="flex justify-between items-center mb-2">
                  <div className="flex items-center">
                    <AlertTriangle className="h-4 w-4 mr-2 text-yellow-500" />
                    <h3 className="font-medium text-gray-900 dark:text-gray-100">{source.name}</h3>
                  </div>
                  <Badge className={getSeverityColor(source.severity)}>
                    {source.severity}
                  </Badge>
                </div>
                <p className="text-sm text-gray-500 dark:text-gray-400 mb-2">{source.description}</p>
                <div className="flex justify-between items-center text-sm">
                  <span className="text-gray-500 dark:text-gray-400">
                    {source.count} incidents detected
                  </span>
                  <span className="flex items-center">
                    {source.percentage}% of threats {getTrendIcon(source.trend)}
                  </span>
                </div>
                <div className="mt-2">
                  <Progress value={source.percentage} className="h-1" />
                </div>
              </div>
            ))}
          </div>
        </TabsContent>
        <TabsContent value="remediation" className="mt-0">
          <div className="space-y-4">
            {remediations.map((remedy, index) => (
              <div key={index} className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
                <div className="flex justify-between items-center mb-2">
                  <div className="flex items-center">
                    <Settings2 className="h-4 w-4 mr-2 text-blue-500" />
                    <h3 className="font-medium text-gray-900 dark:text-gray-100">{remedy.threat}</h3>
                  </div>
                  <div className="flex space-x-2">
                    <Badge className={getPriorityColor(remedy.priority)}>
                      {remedy.priority} Priority
                    </Badge>
                    {remedy.automatable && (
                      <Badge className="bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200">
                        Auto-Remediation
                      </Badge>
                    )}
                  </div>
                </div>
                <ul className="list-disc list-inside text-sm text-gray-600 dark:text-gray-300 mb-3 pl-1">
                  {remedy.actions.map((action, actionIndex) => (
                    <li key={actionIndex} className="my-1">{action}</li>
                  ))}
                </ul>
                <div className="flex justify-between items-center mt-2">
                  <span className="text-sm text-gray-500 dark:text-gray-400">
                    Difficulty: <span className="font-medium">{remedy.difficulty}</span>
                  </span>
                  <Button size="sm" variant={remedy.automatable ? "default" : "outline"}>
                    {remedy.automatable ? "Auto-Remediate" : "Manual Steps"}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </TabsContent>
      </CardContent>
    </Card>
  );
}
