import {
  AppBar,
  Box,
  Container,
  IconButton,
  MenuItem,
  Select,
  Toolbar,
  Typography,
  Tooltip,
  FormControl,
  InputLabel,
} from "@mui/material";
import RefreshIcon from "@mui/icons-material/Refresh";
import LightModeIcon from "@mui/icons-material/LightMode";
import React from "react";
import AlertsTable from "./components/AlertsTable";

const refreshOptions = [
  { label: "5s", value: 5000 },
  { label: "10s", value: 10000 },
  { label: "30s", value: 30000 },
  { label: "Manual", value: 0 },
];

function App() {
  const [refreshInterval, setRefreshInterval] = React.useState<number>(10000);
  const [lastUpdated, setLastUpdated] = React.useState<Date | null>(null);
  const tableRef = React.useRef<{ reload: () => void } | null>(null);

  const handleManualReload = () => {
    tableRef.current?.reload();
  };

  const handleDataUpdate = () => {
    setLastUpdated(new Date());
  };

  return (
    <Box sx={{ minHeight: "100vh", bgcolor: "#f4f6f8" }}>
      <AppBar position="static" color="primary" elevation={2}>
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            Scaleway Audit Sentinel
          </Typography>
          <Tooltip title="Manual Refresh">
            <IconButton color="inherit" onClick={handleManualReload}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          <FormControl
            size="small"
            variant="outlined"
            sx={{ minWidth: 140, ml: 2, bgcolor: "rgba(255,255,255,0.15)", borderRadius: 1 }}
          >
            <InputLabel sx={{ color: "#fff" }}>Reload</InputLabel>
            <Select
              value={refreshInterval}
              label="Reload"
              onChange={(event) => setRefreshInterval(Number(event.target.value))}
              sx={{
                color: "#fff",
                "& .MuiSvgIcon-root": { color: "#fff" },
              }}
            >
              {refreshOptions.map((option) => (
                <MenuItem key={option.value} value={option.value}>
                  {option.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <Tooltip title="Light theme preview">
            <IconButton color="inherit" sx={{ ml: 1 }}>
              <LightModeIcon />
            </IconButton>
          </Tooltip>
        </Toolbar>
      </AppBar>

      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Typography variant="h5" gutterBottom>
          Active Alerts
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {lastUpdated
            ? `Last updated: ${lastUpdated.toLocaleTimeString()}`
            : "Waiting for first refresh..."}
        </Typography>
        <AlertsTable
          ref={tableRef}
          refreshInterval={refreshInterval}
          onDataUpdate={handleDataUpdate}
        />
      </Container>
    </Box>
  );
}

export default App;

