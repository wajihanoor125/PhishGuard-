<?php

it('shows a scan progress indicator on the homepage', function () {
    $response = $this->get('/');

    $response->assertStatus(200);
    $response->assertSee('id="scanProgress"', false);
    $response->assertSee('id="scanProgressBar"', false);
    $response->assertSee('id="scanProgressText"', false);
});
