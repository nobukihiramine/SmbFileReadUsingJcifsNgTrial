package com.hiramine.smbfilereadusingjcifsngtrial;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;

public class MainActivity extends AppCompatActivity
{
	// Usage :
	// String TARGET_PATH = "smb://[hostname]/[sharename]/[directorys]/[filename]";
	// String USERNAME = "[username]";
	// String PASSWORD = "[password]";

	String TARGET_PATH = "smb://[hostname]/[sharename]/[directorys]/[filename]";
	String USERNAME = "[username]";
	String PASSWORD = "[password]";

	@Override
	protected void onCreate( Bundle savedInstanceState )
	{
		super.onCreate( savedInstanceState );
		setContentView( R.layout.activity_main );

		// アクティビティ呼出し
		Button button = findViewById( R.id.button_smbfileread );
		button.setOnClickListener( view ->
								   {
									   Intent intent = new Intent( this, FileReadActivity.class );
									   intent.putExtra( FileReadActivity.EXTRA_TARGET_PATH, TARGET_PATH );
									   intent.putExtra( FileReadActivity.EXTRA_USERNAME, USERNAME );
									   intent.putExtra( FileReadActivity.EXTRA_PASSWORD, PASSWORD );
									   startActivity( intent );
								   } );
	}
}