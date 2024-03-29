/* SPDX-FileCopyrightText: 2014-present Kriasoft */
/* SPDX-License-Identifier: MIT */

import { Api, GitHub } from "@mui/icons-material";
import { Box, Button, Container, Typography } from "@mui/material";
import { usePageEffect } from "../core/page.js";

export default function Home(): JSX.Element {
  usePageEffect({ title: "Xcel Karate" });

  return (
    <Container sx={{ py: "20vh" }} maxWidth="sm">
      <Typography sx={{ mb: 2 }} variant="h1" align="center">
        Welcome to Xcel Karate!
      </Typography>

      <Typography sx={{ mb: 4 }} variant="h3" align="center">
        Iowa&apos;s most popular Karate Dojo.
      </Typography>

      <Box
        sx={{
          display: "flex",
          justifyContent: "center",
          gridGap: "1rem",
        }}
      >
        <Button
          variant="outlined"
          size="large"
          href={`/api`}
          children="Explorer API"
          startIcon={<Api />}
        />
        <Button
          variant="outlined"
          size="large"
          href="#"
          children="Example Button 2"
          startIcon={<GitHub />}
        />
      </Box>
    </Container>
  );
}
